import resolve from '@rollup/plugin-node-resolve';
import commonjs from '@rollup/plugin-commonjs';
import babel from '@rollup/plugin-babel';
import terser from '@rollup/plugin-terser';

export default {
  input: 'cryptus/cryptus.js',
  output: [{
    file: 'dist/libcryptus-cjs.js',
    format: 'iife',
    name: 'Cryptus',
    globals: {
      'argon2-browser': 'argon2'
    }
  }, {
    file: 'dist/cryptus.js',
    format: 'es',
    name: 'Cryptus'
  }],
  external: ['argon2-browser'],
  plugins: [
    resolve(),
    commonjs(),
    babel({
      babelHelpers: 'bundled',
      exclude: 'node_modules/**',
      presets: ['@babel/preset-env']
    }),
    terser()
  ]
};
