// app.js - Full Advanced AST Cleaner + Renamer + Fallback (Complete Long Version)
// - Parses Lua with luaparse
// - Rewrites vararg patterns ({...})[n] -> argN
// - Rewrites local a,b = ... -> local a,b = arg1, arg2
// - Converts function(...) -> function(arg1, arg2, ...)
// - Heuristically renames primer-like varNNN names when initializer suggests a meaningful name
// - Single-element table inlining: local t = { x } ; local y = t[1] -> local y = x
// - Falls back to regex cleaning when parsing fails
// - Runs on internal port 5001 by default (safe to run alongside server.js on process.env.PORT)
// ========================================================

const express = require("express");
const bodyParser = require("body-parser");
const path = require("path");
const luaparse = require("luaparse");

const app = express();
app.use(bodyParser.json({ limit: "20mb" }));
app.use(bodyParser.urlencoded({ extended: true, limit: "20mb" }));

// Serve index.html if it's present in the repo root
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "ast.html"));
});

// ----------------------------- Helpers -----------------------------
function escapeRegExp(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// Deep AST walker
function walk(node, cb) {
  if (!node || typeof node !== "object") return;
  if (Array.isArray(node)) {
    node.forEach(n => walk(n, cb));
    return;
  }
  cb(node);
  for (const k of Object.keys(node)) {
    if (k === "range") continue;
    const child = node[k];
    if (child && typeof child === "object") walk(child, cb);
  }
}

// safe source extractor
function srcOf(node, code) {
  if (!node || !node.range) return "";
  return code.slice(node.range[0], node.range[1]);
}

// infer human-friendly name heuristically from initializer source
function inferNameFromInit(initSrc) {
  if (!initSrc || typeof initSrc !== "string") return null;
  const s = initSrc;

  // common Roblox patterns
  const mGetService = s.match(/GetService\s*\(\s*["']([\w\s-]+)["']\s*\)/i);
  if (mGetService) {
    const service = mGetService[1].replace(/\s+/g, "").replace(/[^A-Za-z0-9]/g, "");
    if (service.length) return service.charAt(0).toLowerCase() + service.slice(1) + "Service";
  }

  if (/HttpGet\s*\(/i.test(s) || /https?:\/\//i.test(s)) return "httpGetResult";
  if (/loadstring\s*\(/i.test(s) || /\bloadstring\b/.test(s)) return "loaded";
  if (/\bMakeWindow\b/i.test(s)) return "window";
  if (/\bMakeTab\b/i.test(s)) return "tab";
  if (/\bAddSection\b/i.test(s)) return "section";
  if (/\bAddButton\b/i.test(s)) return "button";
  if (/\bAddToggle\b/i.test(s)) return "toggle";
  if (/\bAddSlider\b/i.test(s)) return "slider";
  if (/\bAddDropdown\b/i.test(s)) return "dropdown";
  if (/\bLocalPlayer\b/i.test(s)) return "localPlayer";
  if (/\bPlayers\b/i.test(s) && /\bLocalPlayer\b/i.test(s)) return "localPlayer";

  // fallback: take trailing identifier-like token
  const token = s.match(/([A-Za-z_][A-Za-z0-9_]*)\s*$/);
  if (token) return token[1];

  return null;
}

// produce a unique name given a set of used names
function uniqueName(base, used) {
  base = (base || "v").replace(/[^A-Za-z0-9_]/g, "");
  if (!/^[A-Za-z_]/.test(base)) base = "_" + base;
  let name = base;
  let i = 1;
  while (used.has(name) || /^var\d+$/i.test(name)) {
    name = base + String(i++);
  }
  used.add(name);
  return name;
}

// ----------------------------- Regex fallback (simple, safe) -----------------------------
function regexFallbackClean(code, options = {}) {
  const argPrefix = typeof options.argPrefix === "string" ? options.argPrefix : "arg";
  const maxArgsPerFn = typeof options.maxArgsPerFn === "number" ? options.maxArgsPerFn : 6;

  // Replace ({...})[N] -> argN (best-effort)
  code = code.replace(/\(\{\s*\.{3}\s*\}\)\s*\[\s*(\d+)\s*\]/g, (m, n) => {
    const idx = Number(n);
    if (isFinite(idx) && idx >= 1 && idx <= maxArgsPerFn) return `${argPrefix}${idx}`;
    return `${argPrefix}${n}`;
  });

  // Replace local a,b = ... => local a,b = arg1, arg2, ...
  code = code.replace(/local\s+([A-Za-z0-9_,\s]+)\s*=\s*\.{3}/g, (m, names) => {
    const idents = names.replace(/^local\s+/, "").replace(/\s+/g, "").split(",").filter(Boolean);
    const rhs = idents.map((_, i) => `${argPrefix}${i + 1}`).join(", ");
    return `local ${idents.join(", ")} = ${rhs}`;
  });

  // Replace function(...) -> function()
  code = code.replace(/function\s*\(\s*\.{3}\s*\)/g, "function()");

  // Flatten trivial single-element tables: local t = { x } \n local y = t[1] -> local y = x
  code = code.replace(/local\s+(\w+)\s*=\s*\{\s*([^\}]+?)\s*\}\s*\n\s*local\s+(\w+)\s*=\s*\1\s*\[\s*1\s*\]/g, (m, tname, inner, alias) => {
    return `local ${alias} = ${inner}`;
  });

  // conservative whitespace cleanup
  return code;
}

// ----------------------------- AST-driven cleaner (advanced) -----------------------------
function cleanWithAST(code, options = {}) {
  // default options
  const argPrefix = typeof options.argPrefix === "string" ? options.argPrefix : "arg";
  const maxArgsPerFn = typeof options.maxArgsPerFn === "number" ? options.maxArgsPerFn : 6;
  const enableRenaming = options.enableRenaming === true;

  // parse with luaparse
  let ast;
  try {
    ast = luaparse.parse(code, {
      luaVersion: "5.1",
      ranges: true,
      locations: true,
      scope: true,
      comments: false
    });
  } catch (err) {
    // parse failed
    return { cleaned: code, warnings: ["parse_failed: " + (err && err.message)], renameMap: {} };
  }

  // We'll collect replacements as {start, end, text}
  const replacements = [];

  // 1) Detect functions that use vararg patterns and decide arg counts
  // Map function node -> header info { argCount, argNames }
  const funcHeaderMap = new Map();

  walk(ast, node => {
    if ((node.type === "FunctionDeclaration" || node.type === "FunctionExpression") && node.is_vararg) {
      // Inspect body to find usages of ({...})[N] and local destructuring from vararg
      let maxIdx = 0;

      walk(node.body, inner => {
        // look for index expressions of a table constructor containing a vararg literal
        if (inner.type === "IndexExpression" && inner.base && inner.base.type === "TableConstructorExpression") {
          const base = inner.base;
          const hasVararg = (base.fields || []).some(f => f && f.type === "TableValue" && f.value && f.value.type === "VarargLiteral");
          if (hasVararg && inner.index && inner.index.type === "NumericLiteral" && Number.isFinite(inner.index.value)) {
            maxIdx = Math.max(maxIdx, inner.index.value);
          }
        }

        // look for local a,b = ... (VarargLiteral)
        if (inner.type === "LocalStatement" && inner.init && inner.init.length) {
          for (let i = 0; i < inner.init.length; i++) {
            const initNode = inner.init[i];
            if (initNode && initNode.type === "VarargLiteral") {
              const leftCount = (inner.variables || []).length;
              maxIdx = Math.max(maxIdx, leftCount);
            }
          }
        }
      });

      const argCount = Math.min(maxIdx, maxArgsPerFn);
      const argNames = [];
      for (let i = 1; i <= argCount; ++i) argNames.push(`${argPrefix}${i}`);

      funcHeaderMap.set(node, { argCount, argNames });
    }
  });

  // 2) Replace IndexExpression usages like ({...})[N] inside functions with corresponding arg names
  walk(ast, node => {
    if (node.type === "IndexExpression") {
      // find the enclosing function (smallest one that encloses this node)
      let enclosingFn = null;
      for (const fnNode of funcHeaderMap.keys()) {
        if (fnNode.range && node.range && fnNode.range[0] <= node.range[0] && fnNode.range[1] >= node.range[1]) {
          if (!enclosingFn || (fnNode.range[1] - fnNode.range[0] < enclosingFn.range[1] - enclosingFn.range[0])) {
            enclosingFn = fnNode;
          }
        }
      }
      if (!enclosingFn) return;

      const base = node.base;
      const index = node.index;
      if (!base || base.type !== "TableConstructorExpression" || !index || index.type !== "NumericLiteral") return;

      const hasVararg = (base.fields || []).some(f => f && f.type === "TableValue" && f.value && f.value.type === "VarargLiteral");
      if (!hasVararg) return;

      const hdr = funcHeaderMap.get(enclosingFn);
      if (!hdr) return;
      const idx = index.value;
      if (!Number.isFinite(idx) || idx < 1 || idx > hdr.argCount) return;

      // schedule replacement of entire IndexExpression with arg name
      replacements.push({ start: node.range[0], end: node.range[1], text: hdr.argNames[idx - 1] });
    }
  });

  // 3) Replace local a,b = ... (VarargLiteral) with explicit args when possible
  walk(ast, node => {
    if (node.type === "LocalStatement" && node.init && node.init.length) {
      for (let i = 0; i < node.init.length; ++i) {
        const initNode = node.init[i];
        if (initNode && initNode.type === "VarargLiteral") {
          // find enclosing function (smallest)
          let enclosingFn = null;
          for (const fnNode of funcHeaderMap.keys()) {
            if (fnNode.range && node.range && fnNode.range[0] <= node.range[0] && fnNode.range[1] >= node.range[1]) {
              if (!enclosingFn || (fnNode.range[1] - fnNode.range[0] < enclosingFn.range[1] - enclosingFn.range[0])) {
                enclosingFn = fnNode;
              }
            }
          }
          const hdr = funcHeaderMap.get(enclosingFn);
          const leftVars = (node.variables || []).map(v => (v && v.name) || "").filter(Boolean);
          if (hdr && hdr.argCount > 0 && leftVars.length > 0) {
            const needed = Math.min(leftVars.length, hdr.argCount);
            const rhs = [];
            for (let k = 0; k < needed; ++k) rhs.push(hdr.argNames[k]);
            const newText = `local ${leftVars.join(", ")} = ${rhs.join(", ")}`;
            replacements.push({ start: node.range[0], end: node.range[1], text: newText });
          } else if (leftVars.length > 0) {
            // remove vararg token but keep left side: local a,b =
            const left = leftVars.join(", ");
            replacements.push({ start: node.range[0], end: node.range[1], text: `local ${left} = ` });
          }
        }
      }
    }
  });

  // 4) Replace local x = ({...})[N] -> local x = argN (when inside function detected)
  walk(ast, node => {
    if (node.type === "LocalStatement" && node.init && node.init.length === 1) {
      const initNode = node.init[0];
      if (initNode && initNode.type === "IndexExpression" && initNode.base && initNode.base.type === "TableConstructorExpression") {
        const base = initNode.base;
        const hasVararg = (base.fields || []).some(f => f && f.type === "TableValue" && f.value && f.value.type === "VarargLiteral");
        const indexNode = initNode.index;
        if (!hasVararg || !indexNode || indexNode.type !== "NumericLiteral") return;

        // find enclosing function
        let enclosingFn = null;
        for (const fnNode of funcHeaderMap.keys()) {
          if (fnNode.range && node.range && fnNode.range[0] <= node.range[0] && fnNode.range[1] >= node.range[1]) {
            if (!enclosingFn || (fnNode.range[1] - fnNode.range[0] < enclosingFn.range[1] - enclosingFn.range[0])) {
              enclosingFn = fnNode;
            }
          }
        }
        const hdr = funcHeaderMap.get(enclosingFn);
        const idxVal = indexNode.value;
        if (hdr && idxVal >= 1 && idxVal <= hdr.argCount) {
          const argName = hdr.argNames[idxVal - 1];
          const leftVar = (node.variables && node.variables[0] && node.variables[0].name) || null;
          if (leftVar) {
            replacements.push({ start: node.range[0], end: node.range[1], text: `local ${leftVar} = ${argName}` });
          } else {
            replacements.push({ start: node.range[0], end: node.range[1], text: argName });
          }
        }
      }
    }
  });

  // 5) Replace function header "(...)" -> "(arg1, arg2, ...)" or "()"
  for (const [fnNode, hdr] of funcHeaderMap.entries()) {
    if (!fnNode.range) continue;
    const fnSrc = srcOf(fnNode, code);
    if (!fnSrc) continue;
    const paramMatch = fnSrc.match(/\(\s*\.\.\.\s*\)/);
    const argText = hdr.argCount && hdr.argCount > 0 ? `(${hdr.argNames.join(", ")})` : "()";
    if (paramMatch) {
      const absStart = fnNode.range[0] + paramMatch.index;
      const absEnd = absStart + paramMatch[0].length;
      replacements.push({ start: absStart, end: absEnd, text: argText });
    } else {
      // fallback: find "(...)" inside source as fallback
      const pos = code.indexOf("(...)", fnNode.range[0]);
      if (pos >= 0 && pos + 4 < fnNode.range[1]) {
        replacements.push({ start: pos, end: pos + 5, text: argText });
      }
    }
  }

  // 6) Single-element table flattening (conservative): detect local t = { expr } then local x = t[1]
  const tableDefs = []; // { name, exprSrc, declRange }
  walk(ast, node => {
    if (node.type === "LocalStatement" && node.init && node.init.length === 1) {
      const init = node.init[0];
      if (init && init.type === "TableConstructorExpression") {
        const fields = init.fields || [];
        if (fields.length === 1 && fields[0].type === "TableValue") {
          const inner = fields[0].value;
          if (inner && ["Identifier", "StringLiteral", "NumericLiteral", "BooleanLiteral", "NilLiteral", "CallExpression", "MemberExpression", "IndexExpression"].includes(inner.type)) {
            const tblNameNode = node.variables && node.variables[0];
            const tblName = tblNameNode && tblNameNode.name;
            if (tblName) tableDefs.push({ name: tblName, exprSrc: srcOf(inner, code), declRange: node.range });
          }
        }
      }
    }
  });

  if (tableDefs.length > 0) {
    walk(ast, node => {
      if (node.type === "LocalStatement" && node.init && node.init.length === 1) {
        const init = node.init[0];
        if (init && init.type === "IndexExpression" && init.index && init.index.type === "NumericLiteral" && init.index.value === 1) {
          const base = init.base;
          if (base && base.type === "Identifier") {
            const found = tableDefs.find(t => t.name === base.name);
            if (found) {
              const leftVar = (node.variables && node.variables[0] && node.variables[0].name) || null;
              if (leftVar) {
                replacements.push({ start: node.range[0], end: node.range[1], text: `local ${leftVar} = ${found.exprSrc}` });
              }
            }
          }
        }
      }
    });
  }

  // 7) Variable renaming: conservative mapping for varNNN style locals when we can infer a name
  const usedNames = new Set();
  walk(ast, n => {
    if (n.type === "Identifier" && typeof n.name === "string") usedNames.add(n.name);
  });

  const localDecls = [];
  walk(ast, n => {
    if (n.type === "LocalStatement" && n.variables && n.variables.length) {
      const inits = n.init || [];
      for (let vi = 0; vi < n.variables.length; ++vi) {
        const v = n.variables[vi];
        const initNode = inits[vi] || inits[0] || null;
        const initSrc = initNode ? srcOf(initNode, code) : "";
        localDecls.push({ idName: v && v.name, initSrc, idNode: v, declNode: n });
      }
    }
  });

  const renameMap = new Map();
  for (const decl of localDecls) {
    const name = decl.idName;
    if (!name) continue;
    // only target obfuscated names that look like var123 or _something (conservative)
    if (!/^var\d+$/i.test(name) && !/^_[A-Za-z0-9]+$/.test(name)) continue;
    const guess = inferNameFromInit(decl.initSrc) || null;
    if (!guess) continue;
    const newName = uniqueName(guess, usedNames);
    renameMap.set(name, newName);
  }

  // schedule identifier replacements for renameMap if renaming enabled
  if (enableRenaming && renameMap.size > 0) {
    walk(ast, n => {
      if (n.type === "Identifier" && typeof n.name === "string" && n.range && renameMap.has(n.name)) {
        replacements.push({ start: n.range[0], end: n.range[1], text: renameMap.get(n.name) });
      }
    });
  }

  // 8) Deduplicate and apply replacements descending by position
  replacements.sort((a, b) => b.start - a.start || a.end - b.end);

  // Filter overlapping replacements: if a replacement overlaps a previously kept replacement, skip it
  const applied = [];
  let out = code;
  for (const r of replacements) {
    if (typeof r.start !== "number" || typeof r.end !== "number" || r.start >= r.end) continue;
    // check overlap with already applied ones
    let overlap = false;
    for (const a of applied) {
      if (!(r.end <= a.start || r.start >= a.end)) { overlap = true; break; }
    }
    if (overlap) continue;
    // apply replacement on current out by slicing relative to original code positions
    // Note: because we apply in descending order and indices are from original code, slicing is safe
    out = out.slice(0, r.start) + r.text + out.slice(r.end);
    applied.push({ start: r.start, end: r.start + (r.text ? r.text.length : 0) });
  }

  // final lightweight cleanups
  out = out.replace(/\t/g, "  ").replace(/[ \t]+$/gm, "");

  // prepare renameMap object
  const renameMapObj = {};
  for (const [k, v] of renameMap.entries()) renameMapObj[k] = v;

  return { cleaned: out, warnings: [], renameMap: renameMapObj };
}

// ----------------------------- End AST cleaner -----------------------------

// ----------------------------- Express endpoints -----------------------------

// /clean_ast - advanced AST cleaning (returns renameMap & warnings)
app.post("/clean_ast", (req, res) => {
  try {
    const { code = "", options = {} } = req.body || {};
    const opts = {
      argPrefix: typeof options.argPrefix === "string" ? options.argPrefix : "arg",
      maxArgsPerFn: typeof options.maxArgsPerFn === "number" ? options.maxArgsPerFn : 6,
      enableRenaming: options.enableRenaming === true
    };

    const result = cleanWithAST(String(code), opts);

    // If parsing failed, the result will have warnings with parse_failed; fallback to regex
    if (Array.isArray(result.warnings) && result.warnings.some(w => typeof w === "string" && w.startsWith("parse_failed"))) {
      const fallback = regexFallbackClean(String(code), opts);
      return res.json({ success: true, cleaned: fallback, fallback: true, warnings: result.warnings, renameMap: {} });
    }

    return res.json({ success: true, cleaned: result.cleaned, warnings: result.warnings || [], renameMap: result.renameMap || {} });
  } catch (err) {
    console.error("clean_ast error:", err && err.stack || err);
    res.status(500).json({ success: false, error: String(err) });
  }
});

// /clean - convenience hybrid endpoint: try AST first, fallback to regex
app.post("/clean", (req, res) => {
  try {
    const { code = "", options = {} } = req.body || {};
    const opts = {
      argPrefix: typeof options.argPrefix === "string" ? options.argPrefix : "arg",
      maxArgsPerFn: typeof options.maxArgsPerFn === "number" ? options.maxArgsPerFn : 6,
      enableRenaming: options.enableRenaming === true
    };

    const astResult = cleanWithAST(String(code), opts);
    if (Array.isArray(astResult.warnings) && astResult.warnings.some(w => typeof w === "string" && w.startsWith("parse_failed"))) {
      const fallback = regexFallbackClean(String(code), opts);
      return res.json({ success: true, cleaned: fallback, fallback: true, warnings: astResult.warnings || [] });
    }

    return res.json({ success: true, cleaned: astResult.cleaned, warnings: astResult.warnings || [], renameMap: astResult.renameMap || {} });
  } catch (err) {
    console.error("clean error:", err && err.stack || err);
    res.status(500).json({ success: false, error: String(err) });
  }
});

// health check
app.get("/health", (req, res) => res.json({ ok: true }));

// ----------------------------- Start server (internal port) -----------------------------

// IMPORTANT: Use an internal fixed port so app.js doesn't conflict with server.js on process.env.PORT
const PORT = 5001;

app.listen(PORT, () => {
  console.log(`Advanced AST Primer Cleaner running on internal port ${PORT}`);
});
