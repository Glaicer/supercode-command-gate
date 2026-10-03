import { chmod, mkdir, readFile, symlink, writeFile } from "node:fs/promises";

export const REWRITTEN_COMMAND =
  "touch rewritten.marker; pwd; printenv HOME CDPATH";

export async function runRtkCases({
  root,
  boot,
  setCases,
  baseURL,
  aar,
  modelRequests,
}) {
  await mkdir(`${root}/rtk/project/other`, { recursive: true });
  await symlink("other", `${root}/rtk/project/linked-other`);
  const rewriterPath = `${root}/rtk/fixture-rtk`;
  await writeFile(
    rewriterPath,
    `#!${process.execPath}
const fs = require('node:fs');
fs.appendFileSync(${JSON.stringify(`${root}/rtk/rewrites.jsonl`)}, JSON.stringify({args: process.argv.slice(2), cwd: process.cwd(), env: process.env}) + '\\n');
const command = process.argv[3];
if (command.includes('rtk-empty')) process.stdout.write('  \\n');
else if (command.includes('rtk-failure')) { process.stdout.write('touch must-not-run.marker'); process.exitCode = 3; }
else if (command.includes('rtk-timeout') || command.includes('fixture-cancel') || command.includes('fixture-unload')) {
  const token = command.match(/rtk-timeout|fixture-cancel|fixture-unload/)[0];
  fs.writeFileSync(${JSON.stringify(`${root}/rtk/`)} + token + '.pid', String(process.pid));
  require('node:child_process').spawn(process.execPath, ['-e', "setTimeout(() => require('node:fs').writeFileSync(" + JSON.stringify(${JSON.stringify(`${root}/rtk/`)} + token + '.late') + ", ''), 6000)"]);
  setTimeout(() => process.stdout.write('touch must-not-run.marker'), 6000);
}
else if (command.includes('rtk-deny')) process.stdout.write('FIXTURE=fixture-deny touch rewritten-denied.marker');
else if (command.includes('rtk-heredoc') || command.includes('rtk-redirection')) process.stdout.write(command + '\\n');
else process.stdout.write(${JSON.stringify(REWRITTEN_COMMAND)} + '\\n');
`,
  );
  await chmod(rewriterPath, 0o755);
  const cases = [
    {
      name: "rtk-success",
      call: {
        tool: "shell",
        arguments: {
          command: "touch original.marker",
          workdir: `${root}/rtk/project/linked-other`,
        },
      },
      marker: "other/rewritten.marker",
      environment: {
        PATH: process.env.PATH,
        HOME: `${root}/rtk/home/session-home`,
        SHELL: "/bin/bash",
        CDPATH: `${root}/rtk/project/other`,
        SECRET: "not-for-rewrite",
      },
    },
    ...["rtk-empty", "rtk-failure", "rtk-timeout", "rtk-deny"].map((name) => ({
      name,
      call: { tool: "shell", arguments: { command: `touch ${name}.marker` } },
      marker:
        name === "rtk-deny" ? "rewritten-denied.marker" : `${name}.marker`,
      ownedProcess: name === "rtk-timeout",
    })),
    ...["fixture-cancel", "fixture-unload"].map((name) => ({
      name,
      call: { tool: "shell", arguments: { command: `touch ${name}.marker` } },
      marker: `${name}.marker`,
      ownedProcess: true,
      cancellation: true,
    })),
    ...["rtk-empty-deny", "rtk-failure-deny"].map((name) => ({
      name,
      call: {
        tool: "shell",
        arguments: { command: `FIXTURE=fixture-deny touch ${name}.marker` },
      },
      marker: `${name}.marker`,
    })),
    {
      name: "rtk-redirection",
      call: {
        tool: "shell",
        arguments: { command: "printf fixture-deny > rtk-redirection.marker" },
      },
      marker: "rtk-redirection.marker",
    },
    {
      name: "rtk-heredoc",
      call: {
        tool: "shell",
        arguments: {
          command: "cat <<'EOF' > rtk-heredoc.marker\nfixture-deny\nEOF",
        },
      },
      marker: "rtk-heredoc.marker",
    },
    {
      name: "rtk-read",
      call: { tool: "read", arguments: { path: "/etc/hostname" } },
    },
  ];
  setCases(cases);
  const result = await boot({
    name: "rtk",
    root: `${root}/rtk`,
    baseURL,
    aar,
    modelRequests,
    cases,
    bypass: true,
    pluginOptions: { commandRewriter: "rtk", rewriterPath },
  });
  result.rewrites = (
    await readFile(`${root}/rtk/rewrites.jsonl`, "utf8").catch(() => "")
  )
    .trim()
    .split("\n")
    .filter(Boolean)
    .map(JSON.parse);
  result.fallbackBoots = [];
  for (const mode of ["absent", "none"]) {
    const name = `rtk-${mode}`;
    const fallbackCases = [
      {
        name,
        call: { tool: "shell", arguments: { command: `touch ${name}.marker` } },
        marker: `${name}.marker`,
      },
      {
        name: `${name}-deny`,
        call: {
          tool: "shell",
          arguments: {
            command: `FIXTURE=fixture-deny touch ${name}-deny.marker`,
          },
        },
        marker: `${name}-deny.marker`,
      },
    ];
    setCases(fallbackCases);
    result.fallbackBoots.push(
      await boot({
        name,
        root: `${root}/${name}`,
        baseURL,
        aar,
        modelRequests,
        cases: fallbackCases,
        pluginOptions: {
          commandRewriter: mode === "none" ? "none" : "rtk",
          rewriterPath: mode === "none" ? rewriterPath : `${root}/missing-rtk`,
        },
      }),
    );
  }
  return result;
}
