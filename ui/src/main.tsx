import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { FormEvent } from "react";
import { createRoot } from "react-dom/client";
import { Api, ApiError, permissions } from "./api";
import type { Controls, Operation, Session, Submission } from "./api";
import { Failure, Heading, Mark, Message } from "./components";
import { PlanRestore } from "./restore";
import { publicError, useResource, useRoute } from "./state";
import type { Accepted, Route } from "./state";
import { ArtifactDetail, Artifacts, JobDetail, Jobs, Overview } from "./views";
import "./styles.css";

function App() {
  const [session, setSession] = useState<Session | null>();
  const [problem, setProblem] = useState<ApiError>();
  const [revision, retry] = useState(0);
  useEffect(() => {
    const controller = new AbortController();
    void new Api(controller.signal).session().then(
      data => { if (!controller.signal.aborted) setSession(data); },
      error => {
        if (controller.signal.aborted) return;
        const issue = publicError(error);
        if (issue.status !== 401) setProblem(issue);
        setSession(null);
      },
    );
    return () => controller.abort();
  }, [revision]);
  const signedOut = useCallback(() => setSession(null), []);
  if (session === undefined) return <main className="sign-in"><Message>Checking session…</Message></main>;
  if (session) return <Console session={session} onSignOut={signedOut} />;
  return <SignIn error={problem} onSignIn={data => { setProblem(undefined); setSession(data); }}
    retry={() => { setSession(undefined); setProblem(undefined); retry(n => n + 1); }} />;
}

function SignIn({ onSignIn, error, retry }:
  { onSignIn: (session: Session) => void; error?: ApiError; retry: () => void }) {
  const [issue, setIssue] = useState<ApiError>();
  const [busy, setBusy] = useState(false);
  const controller = useMemo(() => new AbortController(), []);
  useEffect(() => () => controller.abort(), [controller]);
  async function login(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (busy) return;
    const form = event.currentTarget;
    const data = new FormData(form);
    const token = data.get("token");
    form.reset();
    data.delete("token");
    if (typeof token !== "string") return;
    setBusy(true);
    setIssue(undefined);
    try {
      const session = await new Api(controller.signal).login(token);
      if (!controller.signal.aborted) onSignIn(session);
    } catch (error) {
      if (!controller.signal.aborted) setIssue(publicError(error));
    } finally {
      if (!controller.signal.aborted) setBusy(false);
    }
  }
  return <main className="sign-in">
    <section className="panel sign-in-card">
      <div className="identity"><Mark /><span>parsBackUp</span><span className="fixture">Fixture</span></div>
      <h1>Sign in</h1>
      <form onSubmit={login}>
        <label htmlFor="token">Operator token</label>
        <input id="token" name="token" type="password" required minLength={43} maxLength={43}
          autoComplete="off" spellCheck={false} />
        <button disabled={busy}>{busy ? "Signing in…" : "Sign in"}</button>
      </form>
      {issue && <Failure error={issue} />}
      {error && <Failure error={error} retry={retry} />}
    </section>
  </main>;
}

type Pending = { input: Submission; key: string; issue?: ApiError; retryAt: number };

function Console({ session, onSignOut }: { session: Session; onSignOut: () => void }) {
  const route = useRoute();
  const routeKey = `${route.view}:${"id" in route ? route.id : ""}`;
  const scope = useMemo(() => new AbortController(), []);
  const endSession = useCallback(() => {
    scope.abort();
    onSignOut();
  }, [scope, onSignOut]);
  const api = useMemo(() => new Api(scope.signal, session.csrf_token, endSession),
    [scope, session.csrf_token, endSession]);
  const [accepted, setAccepted] = useState<Accepted>();
  const [pending, setPending] = useState<Pending>();
  const [actionError, setActionError] = useState<ApiError>();
  const [invalidIntent, setInvalidIntent] = useState<string>();
  const [loggingOut, setLoggingOut] = useState(false);
  const running = useRef(false);
  const main = useRef<HTMLElement>(null);
  const [revision, refresh] = useState(0);
  const health = useResource(useCallback((signal: AbortSignal) => api.health(signal), [api]), revision);
  const profiles = useResource(useCallback((signal: AbortSignal) => api.profiles(signal), [api]), revision);
  const [now, setNow] = useState(Date.now);
  const can = (operation: Operation) => !!health.value?.job_admission &&
    !!profiles.value?.find(profile => profile.id === "default")?.operations.includes(operation) &&
    session.permissions.includes(permissions[operation]);

  useEffect(() => () => scope.abort(), [scope]);
  useEffect(() => {
    const expiry = session.expires_unix_ms;
    if (expiry === null) return;
    const expire = () => { if (Date.now() >= expiry) endSession(); };
    const timer = setTimeout(expire, Math.max(0, Math.min(expiry - Date.now(), 2_147_483_647)));
    document.addEventListener("visibilitychange", expire);
    return () => {
      clearTimeout(timer);
      document.removeEventListener("visibilitychange", expire);
    };
  }, [session.expires_unix_ms, endSession]);
  useEffect(() => { main.current?.focus(); }, [routeKey]);
  useEffect(() => {
    if (!pending?.issue || pending.retryAt === 0) return;
    setNow(Date.now());
    const timer = setInterval(() => setNow(Date.now()), 250);
    return () => clearInterval(timer);
  }, [pending]);

  async function send(attempt: Pending) {
    if (running.current || scope.signal.aborted || Date.now() < attempt.retryAt) return;
    running.current = true;
    setActionError(undefined);
    setPending({ ...attempt, issue: undefined });
    try {
      const { data, retryAfter } = await api.submit(attempt.input, attempt.key);
      if (scope.signal.aborted) return;
      setAccepted({ job: data, retryAfter, receivedAt: Date.now() });
      setPending(undefined);
      location.hash = `#/jobs/${data.id}`;
    } catch (error) {
      if (scope.signal.aborted) return;
      const issue = publicError(error);
      if (issue.ambiguous || issue.status === 429) {
        setPending({ ...attempt, issue, retryAt: Date.now() + (issue.retryAfter ?? 0) });
      } else {
        if (attempt.input.operation === "restore" &&
          (issue.code === "INTENT_EXPIRED" || issue.code === "INTENT_CONFLICT")) {
          setInvalidIntent(attempt.input.body.intent_id);
        }
        setPending(undefined);
        setActionError(issue);
      }
    } finally {
      running.current = false;
    }
  }

  async function logout() {
    setActionError(undefined);
    setLoggingOut(true);
    try {
      await api.logout();
      endSession();
    } catch (error) {
      if (!scope.signal.aborted) setActionError(publicError(error));
    } finally {
      if (!scope.signal.aborted) setLoggingOut(false);
    }
  }

  const controls: Controls = {
    can,
    invalidIntent,
    busy: !!pending || loggingOut,
    submit: input => {
      if (pending || loggingOut || scope.signal.aborted) return;
      if (input.operation !== "cancel" && !can(input.operation)) return;
      void send({ input, key: crypto.randomUUID(), retryAt: 0 });
    },
  };
  const currentNav = navigation(route);

  return <>
    <a className="skip" href="#main" onClick={e => { e.preventDefault(); main.current?.focus(); }}>Skip to content</a>
    <header className="top">
      <div className="header-inner">
        <a className="identity" href="#/"><Mark small /><span>parsBackUp</span></a>
        <span className="fixture">Fixture</span>
        <button className="sign-out" onClick={() => void logout()} disabled={loggingOut}>
          {loggingOut ? "Signing out…" : "Sign out"}
        </button>
      </div>
      <nav aria-label="Console" className="nav">
        {([["overview", "#/", "Overview"], ["artifacts", "#/artifacts", "Artifacts"], ["jobs", "#/jobs", "Jobs"]] as const)
          .map(([view, path, title]) => <a key={view} href={path} aria-current={currentNav === view ? "page" : undefined}>{title}</a>)}
      </nav>
    </header>
    <main className="shell" id="main" ref={main} tabIndex={-1}>
      {pending && <section className="pending panel" aria-label="Submission status">
        {pending.issue ? <>
          <Failure error={pending.issue} />
          <p>{pending.issue.ambiguous ? "The outcome is unknown. Retry the same submission or check Jobs."
            : "The request was refused. You can retry when the API is ready."}</p>
          <div className="button-row">
            <button onClick={() => void send(pending)} disabled={pending.retryAt > now && pending.retryAt > Date.now()}>
              Retry same submission
            </button>
            <a href="#/jobs">View jobs</a>
            {!pending.issue.ambiguous && <button className="secondary" onClick={() => setPending(undefined)}>Dismiss</button>}
          </div>
        </> : <Message>Submitting request…</Message>}
      </section>}
      {actionError && <Failure error={actionError} />}
      <div key={routeKey}>
        {route.view === "overview" && <Overview health={health.value} loading={health.loading}
          error={health.error} refresh={() => refresh(n => n + 1)} />}
        {route.view === "artifacts" && <Artifacts api={api} />}
        {route.view === "artifact" && <ArtifactDetail api={api} id={route.id} controls={controls} />}
        {route.view === "jobs" && <Jobs api={api} />}
        {route.view === "job" && <JobDetail api={api} id={route.id}
          accepted={accepted?.job.id === route.id ? accepted : undefined} controls={controls}
          session={session} admission={!!health.value?.job_admission} />}
        {route.view === "restore" && <PlanRestore api={api} artifactId={route.id} controls={controls} />}
        {route.view === "missing" && <><Heading title="Page unavailable" /><a href="#/">Return to overview</a></>}
      </div>
    </main>
  </>;
}

function navigation(route: Route) {
  if (route.view === "job" || route.view === "jobs") return "jobs";
  if (route.view === "artifact" || route.view === "artifacts" || route.view === "restore") return "artifacts";
  return "overview";
}

const root = document.getElementById("root");
if (root) createRoot(root).render(<App />);
