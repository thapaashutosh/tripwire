import { Fragment, type ReactNode } from "react";
import styles from "./SlackMessage.module.css";

/** Renders the small subset of Slack mrkdwn that tripwire/incidents.py emits: *bold*, `code`, ```block```. */
export function SlackMessage({ text, channel = "#sec-alerts" }: { text: string; channel?: string }) {
  const parts = text.split("```");
  return (
    <div className={styles.msg}>
      <div className={styles.meta}>
        <span className={styles.bot}>tripwire</span>
        <span className="faint">to {channel}</span>
      </div>
      <div className={styles.body}>
        {parts.map((part, i) =>
          i % 2 === 1 ? (
            <pre key={i} className={styles.pre}>
              {part.trim()}
            </pre>
          ) : (
            <Fragment key={i}>
              {part
                .split("\n")
                .filter((line) => line.trim() !== "")
                .map((line, j) => (
                  <p key={j}>{inline(line)}</p>
                ))}
            </Fragment>
          ),
        )}
      </div>
    </div>
  );
}

function inline(line: string): ReactNode[] {
  // tokens: *bold* and `code`
  const out: ReactNode[] = [];
  const re = /(\*[^*]+\*|`[^`]+`)/g;
  let last = 0;
  let m: RegExpExecArray | null;
  while ((m = re.exec(line))) {
    if (m.index > last) out.push(line.slice(last, m.index));
    const tok = m[0];
    out.push(
      tok.startsWith("*") ? <strong key={m.index}>{tok.slice(1, -1)}</strong> : <code key={m.index}>{tok.slice(1, -1)}</code>,
    );
    last = m.index + tok.length;
  }
  if (last < line.length) out.push(line.slice(last));
  return out;
}
