module.exports = {
  apps: [
    {
      name: "web",
      script: "server.js",
      env: { PORT: 10000 }
    },
    {
      name: "bot",
      script: "bot.js"
    },
    {
      name: "ast",
      script: "app.js"
    }
  ]
};
