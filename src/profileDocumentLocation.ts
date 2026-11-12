export function locateDocumentPointer(text: string, path: string): { start: number; end: number } | null {
  if (path !== "" && (!path.startsWith("/") || /~(?![01])/u.test(path))) return null;
  try { JSON.parse(text); } catch { return null; }
  const target = path === "" ? [] : path.slice(1).split("/").map((part) => part.replace(/~1/g, "/").replace(/~0/g, "~"));
  let offset = 0;
  let result: { start: number; end: number } | null = null;
  const whitespace = () => { while (/\s/u.test(text[offset] ?? "") && offset < text.length) offset++; };
  const string = () => {
    const start = offset++;
    while (offset < text.length) {
      if (text[offset++] === "\\") offset++;
      else if (text[offset - 1] === '"') break;
    }
    return text.slice(start, offset);
  };
  const value = (parts: string[]) => {
    whitespace();
    const start = offset;
    if (text[offset] === "{") {
      offset++;
      whitespace();
      while (text[offset] !== "}") {
        const key = JSON.parse(string()) as string;
        whitespace();
        offset++;
        value([...parts, key]);
        whitespace();
        if (text[offset] !== ",") break;
        offset++;
        whitespace();
      }
      offset++;
    } else if (text[offset] === "[") {
      offset++;
      whitespace();
      let index = 0;
      while (text[offset] !== "]") {
        value([...parts, String(index++)]);
        whitespace();
        if (text[offset] !== ",") break;
        offset++;
      }
      offset++;
    } else if (text[offset] === '"') string();
    else while (offset < text.length && !/[\s,}\]]/u.test(text[offset]!)) offset++;
    if (parts.length === target.length && parts.every((part, index) => part === target[index])) result = { start, end: offset };
  };
  value([]);
  return result;
}
