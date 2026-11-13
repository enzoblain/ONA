// Node's `util` as far as the bundle uses it (`format`, in a JSON-schema helper of near-api-js): %s, %d, %j and %%.
export function format(template, ...values) {
  let i = 0;
  const text = String(template).replace(/%[sdj%]/g, (m) => {
    if (m === "%%") return "%";
    const v = values[i++];
    return m === "%j" ? JSON.stringify(v) : String(v);
  });
  return [text, ...values.slice(i).map(String)].join(" ");
}

export default { format };
