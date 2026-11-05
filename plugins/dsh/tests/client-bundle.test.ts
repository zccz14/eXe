// The browser half is not a normal import: the harness executes a factory with
// its own `require`, so the only honest test is to run the built bundle the way
// that system will. Anything wrong with the wrapper, the exports, or the two
// registrations fails here instead of in a browser console.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import * as jsxRuntime from "react/jsx-runtime";
import * as react from "react";
import { test } from "node:test";

interface Registration {
  name: string;
  key?: string;
  id?: string;
  order?: number;
  label?: string;
}

interface ModuleRow {
  id: string;
  factory: (require: (specifier: string) => unknown) => {
    inject?: string[];
    apply?: (ctx: unknown) => void;
  };
}

const stub = (specifier: string): unknown => {
  if (specifier === "react") return react;
  if (specifier === "react/jsx-runtime") return jsxRuntime;
  if (specifier === "react-dom") return {};
  if (specifier === "react-dom/client") return {};
  throw new Error(`the bundle asked for ${specifier}, which the shell does not seed`);
};

function loadBundle(): { row: ModuleRow; exports: ReturnType<ModuleRow["factory"]> } {
  const code = readFileSync(new URL("../lib/client.js", import.meta.url), "utf8");
  const rows: ModuleRow[] = [];
  const window = { __ModuleLoader__: { load: (row: ModuleRow) => rows.push(row) } };
  new Function("window", "require", code)(window, stub);
  assert.equal(rows.length, 1, "the bundle must register exactly one module row");
  const row = rows[0]!;
  return { row, exports: row.factory(stub) };
}

test("the bundle registers itself as this package and exports a cordis plugin", () => {
  const { row, exports } = loadBundle();
  assert.equal(row.id, "dsh-plugin-exe");
  assert.deepEqual(exports.inject, ["slots"]);
  assert.equal(typeof exports.apply, "function");
});

test("apply puts one row in the sidebar and one page in the main column, under one id", () => {
  const { exports } = loadBundle();
  const registrations: Array<{ options: Registration; component: unknown }> = [];
  const ctx = {
    slots: {
      inject: (_name: string, contribute: () => () => void) => void contribute(),
      register: (options: Registration, component: unknown) => {
        registrations.push({ options, component });
        return () => undefined;
      },
    },
  };
  exports.apply?.(ctx);
  assert.deepEqual(
    registrations.map((entry) => entry.options),
    [
      { name: "main", key: "exe" },
      { name: "sidebar.panellist", id: "exe", order: 40, label: "eXe" },
    ],
  );
  const panel = registrations[0]?.component as (props: Record<string, never>) => unknown;
  const markup = renderToStaticMarkup(createElement(panel as never));
  assert.match(markup, /eXe/);
  assert.match(markup, /载入中/);
  const icon = registrations[1]?.component as (props: { size: number; active: boolean }) => unknown;
  assert.match(renderToStaticMarkup(createElement(icon as never, { size: 18, active: true })), /<svg/);
});
