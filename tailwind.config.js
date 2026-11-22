/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./web/**/*.html",
    "./web/js/**/*.js"
  ],
  safelist: [
    {
      pattern: /(bg|text|border)-(emerald|rose|amber|cyan|indigo|sky|violet|slate)-(300|400|500|600|700|800|900|950)/,
      variants: ['hover', 'focus']
    },
    'bg-rose-950/70',
    'bg-amber-950/80',
    'bg-emerald-950/80',
    'bg-rose-950/80',
    'border-emerald-800/60',
    'border-rose-800/60',
    'border-amber-800/40',
    'hover:bg-emerald-900/60',
    'hover:bg-slate-800/30',
    'hover:bg-rose-950/30'
  ],
  theme: {
    extend: {
      fontFamily: {
        sans: ['"Plus Jakarta Sans"', 'Inter', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'monospace'],
      },
    },
  },
  plugins: [],
}
