import type { ReactNode } from "react";
import type { ApiError, Job } from "./api";
import { jobStates } from "./api";

export function Mark({ small = false }: { small?: boolean }) {
  return <span className={small ? "brand-mark small" : "brand-mark"} aria-hidden="true">
    <i /><i /><i />
  </span>;
}

export function Status({ value }: { value: Job["state"] }) {
  return <span className={`status status-${value}`}>{jobStates[value]}</span>;
}

export function Heading({ title, children }: { title: string; children?: ReactNode }) {
  return <div className="heading"><h1>{title}</h1>{children}</div>;
}

export function Message({ children }: { children: ReactNode }) {
  return <p className="message" role="status">{children}</p>;
}

export function Failure({ error, retry }: { error: ApiError; retry?: () => void }) {
  return <div className="failure" role="alert">
    <p>{error.message}</p>
    {error.requestId && <p className="metadata">Request <code>{error.requestId}</code></p>}
    {retry && <button className="secondary" onClick={retry}>Refresh</button>}
  </div>;
}

export function Facts({ rows }: { rows: [string, ReactNode][] }) {
  return <dl className="facts">{rows.map(([label, value]) =>
    <div key={label}><dt>{label}</dt><dd>{value}</dd></div>)}</dl>;
}

const formatter = new Intl.DateTimeFormat(undefined, {
  dateStyle: "medium", timeStyle: "short",
});

export function date(ms: number) {
  const stamp = new Date(ms);
  return <time dateTime={stamp.toISOString()}>{formatter.format(stamp)}</time>;
}

export function Pager({ number, canBack, canNext, previous, next }:
  { number: number; canBack: boolean; canNext: boolean; previous: () => void; next: () => void }) {
  return <div className="pager" aria-label="Pagination">
    <span className="metadata">Page {number}</span>
    <button className="secondary" disabled={!canBack} onClick={previous}>Previous</button>
    <button className="secondary" disabled={!canNext} onClick={next}>Next page</button>
  </div>;
}
