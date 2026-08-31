import { spawnSync } from "node:child_process";
import { resolve } from "node:path";

const wrapper = resolve("gradle/wrapper/gradle-wrapper.jar");
const result = spawnSync(
  "java",
  [
    "-classpath",
    wrapper,
    "org.gradle.wrapper.GradleWrapperMain",
    ...process.argv.slice(2),
  ],
  { stdio: "inherit" },
);

if (result.error) {
  throw result.error;
}
process.exitCode = result.status ?? 1;
