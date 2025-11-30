// Example Node.js/Express backend implementing /clean_ast
// This endpoint accepts a Lua AST JSON, applies the transformation,
// and returns the cleaned AST.

const express = require('express');
const app = express();
app.use(express.json());

// --- Core transformation logic ---
function transformVarargFunction(func) {
  if (!func.is_vararg) return;

  const body = func.body;
  let argsLocalName = null;
  let tableItems = null;
  let localStmtIndex = null;

  // Step 1: detect local args = { ... }
  for (let i = 0; i < body.length; i++) {
    const stmt = body[i];
    if (
      stmt.type === "LocalStatement" &&
      stmt.names.length === 1 &&
      stmt.values &&
      stmt.values.length === 1 &&
      stmt.values[0].type === "TableConstructor"
    ) {
      argsLocalName = stmt.names[0].name;
      tableItems = stmt.values[0].entries;
      localStmtIndex = i;
      break;
    }
  }

  if (!argsLocalName) return;

  // Step 2: build parameters
  const paramNames = tableItems.map((_, i) => `p${i + 1}`);

  func.parameters = paramNames.map((n) => ({ type: "Identifier", name: n }));
  func.is_vararg = false;

  // Step 3: rewrite args[i] inside
  function rewrite(node) {
    if (!node || typeof node !== "object") return;

    if (node.type === "IndexExpression") {
      if (
        node.base && node.base.type === "Identifier" &&
        node.base.name === argsLocalName &&
        node.index && node.index.type === "NumberLiteral"
      ) {
        const idx = node.index.value;
        const replacement = paramNames[idx - 1];
        if (replacement) {
          node.type = "Identifier";
          node.name = replacement;
          delete node.base;
          delete node.index;
        }
      }
    }

    for (const key in node) {
      const value = node[key];
      if (Array.isArray(value)) {
        value.forEach((child) => rewrite(child));
      } else if (typeof value === "object" && value !== null) {
        rewrite(value);
      }
    }
  }

  body.forEach((stmt) => rewrite(stmt));

  // Step 4: remove the original local statement
  if (localStmtIndex !== null) body.splice(localStmtIndex, 1);
}

function transform(ast) {
  function visit(node) {
    if (!node || typeof node !== "object") return;

    if (node.type === "FunctionDeclaration") {
      transformVarargFunction(node);
    }

    for (const key in node) {
      const value = node[key];
      if (Array.isArray(value)) {
        value.forEach((child) => visit(child));
      } else if (typeof value === "object" && value !== null) {
        visit(value);
      }
    }
  }

  visit(ast);
  return ast;
}

// --- API endpoint ---
app.post('/clean_ast', (req, res) => {
  try {
    const ast = req.body;
    const cleaned = transform(ast);
    res.json(cleaned);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.listen(5001, () => console.log('API running on port 5001'));
