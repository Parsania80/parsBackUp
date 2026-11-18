import { useEffect, useState } from "react";
import { ApiError, terminal, uuid } from "./api";
import type { Api, Job, Page } from "./api";

export type Route =
  | { view: "overview" | "artifacts" | "jobs" | "profiles" | "missing" }
  | { view: "artifact" | "job" | "restore"; id: string };

export function readRoute(): Route {
  const hash = location.hash;
  if (!hash || hash === "#/") return { view: "overview" };
  if (hash === "#/artifacts") return { view: "artifacts" };
  if (hash === "#/jobs") return { view: "jobs" };
  if (hash === "#/profiles") return { view: "profiles" };
  if (!hash.startsWith("#/")) return { view: "missing" };
  const [, segment, id, extra] = hash.split("/");
  if (extra !== undefined || !uuid(id)) return { view: "missing" };
  switch (segment) {
    case "artifacts": return { view: "artifact", id };
    case "jobs": return { view: "job", id };
    case "restore": return { view: "restore", id };
    default: return { view: "missing" };
  }
}

export function useRoute() {
  const [route, setRoute] = useState(readRoute);
  useEffect(() => {
    const update = () => setRoute(readRoute());
    window.addEventListener("hashchange", update);
    return () => window.removeEventListener("hashchange", update);
  }, []);
  return route;
}

export type Resource<T> = { value?: T; error?: ApiError; loading: boolean };
export const publicError = (error: unknown) => error instanceof ApiError
  ? error : new ApiError(0, "UNAVAILABLE", undefined, undefined, "The console could not complete this request.");

export function useResource<T>(load: (signal: AbortSignal) => Promise<T>, revision = 0): Resource<T> {
  const [resource, setResource] = useState<Resource<T>>({ loading: true });
  useEffect(() => {
    const controller = new AbortController();
    setResource({ loading: true });
    void load(controller.signal).then(
      value => { if (!controller.signal.aborted) setResource({ value, loading: false }); },
      error => { if (!controller.signal.aborted) setResource({ error: publicError(error), loading: false }); },
    );
    return () => controller.abort();
  }, [load, revision]);
  return resource;
}

export function usePage<T>(load: (signal: AbortSignal, after?: string) => Promise<Page<T>>) {
  const [cursors, setCursors] = useState<(string | undefined)[]>([undefined]);
  const [revision, refresh] = useState(0);
  const after = cursors.at(-1);
  const [resource, setResource] = useState<Resource<Page<T>>>({ loading: true });
  useEffect(() => {
    const controller = new AbortController();
    setResource({ loading: true });
    void load(controller.signal, after).then(
      value => { if (!controller.signal.aborted) setResource({ value, loading: false }); },
      error => { if (!controller.signal.aborted) setResource({ error: publicError(error), loading: false }); },
    );
    return () => controller.abort();
  }, [load, after, revision]);
  return {
    ...resource, number: cursors.length, canBack: cursors.length > 1,
    previous: () => setCursors(list => list.length > 1 ? list.slice(0, -1) : list),
    next: () => {
      const cursor = resource.value?.next_after;
      if (cursor && !cursors.includes(cursor)) setCursors(list => [...list, cursor]);
    },
    refresh: () => refresh(n => n + 1),
  };
}

export type Accepted = { job: Job; retryAfter?: number; receivedAt: number };

export function useJob(api: Api, id: string, accepted?: Accepted) {
  const [revision, refresh] = useState(0);
  const [state, setState] = useState<Resource<Job>>({
    value: accepted?.job, loading: !accepted,
  });
  useEffect(() => {
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    let due = Date.now();
    let busy = false;
    let ended = false;
    let interval = 2000;
    function schedule(delay: number) {
      due = Date.now() + delay;
      clearTimeout(timer);
      if (!document.hidden && !ended) timer = setTimeout(poll, delay);
    }
    async function poll() {
      if (controller.signal.aborted || busy || ended || document.hidden) return;
      busy = true;
      let nextDelay: number | undefined;
      try {
        const { data, retryAfter } = await api.job(id, controller.signal);
        if (controller.signal.aborted) return;
        setState({ value: data, loading: false });
        ended = terminal(data);
        if (!ended) nextDelay = Math.max(interval, retryAfter ?? 0);
        interval = Math.min(interval * 2, 10_000);
      } catch (error) {
        if (controller.signal.aborted) return;
        const issue = publicError(error);
        setState(previous => ({
          value: issue.ambiguous || issue.status === 429 ? previous.value : undefined,
          error: issue, loading: false,
        }));
        if (issue.status === 429 || issue.ambiguous) nextDelay = Math.max(10_000, issue.retryAfter ?? 0);
        else ended = true;
      } finally {
        busy = false;
        if (nextDelay !== undefined && !controller.signal.aborted) schedule(nextDelay);
      }
    }
    function visibility() {
      clearTimeout(timer);
      if (!document.hidden && !busy && !ended) schedule(Math.max(0, due - Date.now()));
    }
    document.addEventListener("visibilitychange", visibility);
    if (accepted && revision === 0) {
      setState({ value: accepted.job, loading: false });
      ended = terminal(accepted.job);
    }
    const wait = accepted
      ? Math.max(0, accepted.receivedAt + (accepted.retryAfter ?? 2000) - Date.now()) : 0;
    if (revision > 0) ended = false;
    schedule(revision > 0 ? 0 : wait);
    return () => {
      controller.abort();
      clearTimeout(timer);
      document.removeEventListener("visibilitychange", visibility);
    };
  }, [api, id, accepted, revision]);
  return { ...state, refresh: () => refresh(n => n + 1) };
}
