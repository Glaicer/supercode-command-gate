import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import http from "node:http";
import path from "node:path";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";

const exec = promisify(execFile);
const gate = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

export async function preparePacked(root) {
  const artifacts = `${root}/packed`;
  await mkdir(artifacts, { recursive: true });
  const manifest = JSON.parse(await readFile(`${gate}/package.json`, "utf8"));
  const result = await exec(
    "npm",
    ["pack", "--json", "--ignore-scripts", "--pack-destination", artifacts],
    { cwd: gate },
  );
  const packed = JSON.parse(result.stdout);
  const pack = Array.isArray(packed) ? packed[0] : packed[manifest.name];
  const tarball = await readFile(`${artifacts}/${pack.filename}`);
  const extracted = `${artifacts}/extracted`;
  await mkdir(extracted);
  await exec("tar", ["-xzf", `${artifacts}/${pack.filename}`, "-C", extracted]);
  const integrity = `sha512-${createHash("sha512").update(tarball).digest("base64")}`;
  const requests = [];
  let origin;
  const registry = http.createServer(async (request, response) => {
    try {
      const route = decodeURIComponent(request.url.split("?")[0]);
      requests.push(route);
      if (route === `/${manifest.name}`) {
        response.setHeader("content-type", "application/json");
        response.end(
          JSON.stringify({
            name: manifest.name,
            "dist-tags": { latest: manifest.version },
            versions: {
              [manifest.version]: {
                ...manifest,
                dist: { tarball: `${origin}/gate.tgz`, integrity },
              },
            },
          }),
        );
      } else if (route === "/gate.tgz") {
        response.end(tarball);
      } else {
        const upstream = await fetch(
          `https://registry.npmjs.org${request.url}`,
          { signal: AbortSignal.timeout(30000) },
        );
        response.writeHead(upstream.status, {
          "content-type":
            upstream.headers.get("content-type") ?? "application/octet-stream",
        });
        response.end(Buffer.from(await upstream.arrayBuffer()));
      }
    } catch (error) {
      response.writeHead(502);
      response.end(String(error));
    }
  });
  await new Promise((resolve) => registry.listen(0, "127.0.0.1", resolve));
  origin = `http://127.0.0.1:${registry.address().port}`;
  return {
    target: manifest.name,
    cache: `${artifacts}/cache`,
    evidence: {
      name: manifest.name,
      version: manifest.version,
      integrity,
      artifact: `${artifacts}/${pack.filename}`,
      files: pack.files.map((file) => file.path),
    },
    async install(opencode, env, cwd) {
      const installEnv = { ...env, NPM_CONFIG_REGISTRY: origin };
      const result = await exec(opencode, ["plugin", "add", manifest.name], {
        env: installEnv,
        cwd,
        timeout: 180000,
      });
      const commands = [
        { action: "add", stdout: result.stdout, stderr: result.stderr },
      ];
      const cache = `${env.XDG_CACHE_HOME}/opencode/npm/${manifest.name}@latest`;
      const generations = await readdir(cache);
      const verified = [];
      for (const generation of generations) {
        const directory = `${cache}/${generation}/node_modules/${manifest.name}`;
        const installed = await readFile(
          `${directory}/package.json`,
          "utf8",
        ).catch(() => null);
        if (!installed) continue;
        assert.equal(JSON.parse(installed).version, manifest.version);
        for (const file of pack.files.filter((file) =>
          file.path.endsWith(".js"),
        )) {
          assert.deepEqual(
            await readFile(`${directory}/${file.path}`),
            await readFile(`${extracted}/package/${file.path}`),
            `installed ${file.path} matches packed source`,
          );
        }
        assert.ok(
          !(await readdir(`${cache}/${generation}/node_modules`)).includes(
            "solid-js",
          ),
          "host supplies Solid",
        );
        verified.push(generation);
      }
      assert.ok(
        verified.length > 0,
        "native installation has a verified cache generation",
      );
      const evidence = { ...this.evidence, commands, generations: verified };
      await writeFile(
        `${cwd}/../installation.json`,
        JSON.stringify(evidence, null, 2),
      );
      return evidence;
    },
    async close() {
      registry.closeAllConnections();
      await new Promise((resolve) => registry.close(resolve));
      await writeFile(
        `${artifacts}/registry-requests.json`,
        JSON.stringify(requests, null, 2),
      );
      await rm(`${artifacts}/cache`, { recursive: true, force: true });
    },
  };
}
