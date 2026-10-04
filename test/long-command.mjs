export function longCommand(marker) {
  return `API_TOKEN=demo-secret FIXTURE=fixture-ask node <<'COMMAND_GATE_LONG_COMMAND' | cat
const payload = '${"0123456789abcdef".repeat(500)}';
const quoted = 'quoted ; | punctuation stays inside the string';
const unicode = '界 🙂 é 👩‍💻';
${Array.from({ length: 20 }, (_, index) => `const line${index} = ${index};`).join("\n")}
console.log(payload.length, quoted, unicode, line19);
COMMAND_GATE_LONG_COMMAND
printf 'once\\n' >> ${marker}; printf 'FINAL_COMMAND_LINE\\n'
`;
}
