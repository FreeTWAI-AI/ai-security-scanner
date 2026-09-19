import { cleanup, render } from "@testing-library/react";
import { afterEach, expect, test } from "vitest";

import { Icon, type IconName } from "../../src/components/Icon";

afterEach(cleanup);

const glyph = (name: IconName, size = 15): string => {
  const { container } = render(<Icon name={name} size={size} />);
  return container.querySelector("svg")?.innerHTML ?? "";
};

test("the results icon is a list, not the warning triangle", () => {
  const warning = glyph("warning");
  expect(warning).toContain("M10.3 3.6");

  for (const size of [15, 17, 19]) {
    const findings = glyph("findings", size);
    expect(findings, `findings at ${size}px matches warning`).not.toBe(glyph("warning", size));
    expect(findings, `findings at ${size}px still draws the warning triangle`).not.toContain("M10.3 3.6");
    expect(findings, `findings at ${size}px matches cases`).not.toBe(glyph("cases", size));
    expect(findings, `findings at ${size}px matches file`).not.toBe(glyph("file", size));
  }
});
