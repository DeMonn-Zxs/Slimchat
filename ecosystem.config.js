module.exports = {
  apps: [
    {
      name: 'slimchat-server',
      script: './server.js',
      cwd: __dirname,
      instances: 1,
      autorestart: true,
      watch: false,
      max_memory_restart: '500M',
      env: {
        NODE_ENV: 'production',
        PORT: 3678,
      },
    },
  ],
};
