import type { Sandbox, SandboxHeldAgent, SandboxPackage, SandboxVersion } from '@/types/sandbox';

/** What the new-version form opens with. */
export type VersionSeed = {
  agent: SandboxHeldAgent | null;
  allowedHosts: string[];
  code: string;
  explanation: string | null;
  image: string;
  memoryMib: number;
  packages: SandboxPackage[];
  runSeconds: number;
  runtime: string;
};

const STARTER_CODE: Record<string, string> = {
  javascript: 'module.exports = (input) => {\n  return { received: input };\n};\n',
  python: 'def main(input):\n    return {"received": input}\n',
};

const STARTER_CHECK: Record<string, string> = {
  javascript: `module.exports = ({ answer, try: attempt }) => {
  const broken = [];

  if (String(answer).toLowerCase().includes('internal')) {
    broken.push('It mentions something internal.');
  }

  return { pass: broken.length === 0, broken };
};
`,
  python: `def main(input):
    answer = str(input["answer"])
    attempt = input["try"]
    broken = []

    if "internal" in answer.lower():
        broken.append("It mentions something internal.")

    return {"pass": not broken, "broken": broken}
`,
};

function starterCode(language: string | null) {
  return STARTER_CODE[language ?? 'python'] ?? STARTER_CODE.python;
}

/** The check a version holding an agent starts from. It reads `answer` and `try`. */
export function starterCheck(language: string | null) {
  return STARTER_CHECK[language ?? 'python'] ?? STARTER_CHECK.python;
}

/** Whether `code` is still only what the form started with, so it may be replaced. */
export function isStarterCode(code: string, language: string | null) {
  return !code.trim() || code === starterCode(language);
}

/** The form's starting values: a copy of `version`, or a blank starter. */
export function seedFromVersion(sandbox: Sandbox, version: SandboxVersion | null): VersionSeed {
  if (!version) {
    return {
      agent: null,
      allowedHosts: [],
      code: sandbox.kind === 'image' ? '' : starterCode(sandbox.language),
      explanation: null,
      image: '',
      memoryMib: 256,
      packages: [],
      runSeconds: 30,
      runtime: '',
    };
  }

  return {
    agent: version.agent,
    allowedHosts: version.allowedHosts,
    code: version.code ?? '',
    explanation: null,
    image: version.kind === 'image' ? version.image : '',
    memoryMib: version.memoryMib,
    packages: version.packages,
    runSeconds: version.runSeconds,
    runtime: version.runtime ?? '',
  };
}
