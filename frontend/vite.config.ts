import {fileURLToPath} from 'node:url';
import {defineConfig, loadEnv} from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig(({mode, command}) => {
  const env = loadEnv(mode, process.cwd(), 'DEVCTL_FRONTEND_');
  const publicOrigin = new URL(process.env.DEVCTL_FRONTEND_PUBLIC_ORIGIN || env.DEVCTL_FRONTEND_PUBLIC_ORIGIN || 'https://127.0.0.1:9090');
  return {
    base: command === 'build' ? '/assets/' : '/',
    plugins: [react()],
    server: {
      host: '127.0.0.1',
      port: 5173,
      strictPort: true,
      origin: publicOrigin.origin,
      hmr: {host: publicOrigin.hostname, protocol: publicOrigin.protocol === 'https:' ? 'wss' : 'ws', clientPort: Number(publicOrigin.port || (publicOrigin.protocol === 'https:' ? 443 : 80)), path: '/__vite_hmr'},
      fs: {strict: true},
    },
    build: {
      outDir: fileURLToPath(new URL('../internal/webui/assets', import.meta.url)),
      emptyOutDir: true,
      cssCodeSplit: false,
      sourcemap: false,
      rolldownOptions: {
        output: {
          entryFileNames: 'app.js',
          chunkFileNames: 'chunk-[name].js',
          assetFileNames: asset => asset.names.some(name => name.endsWith('.css')) ? 'app.css' : '[name][extname]',
          codeSplitting: false,
        },
      },
    },
  };
});
