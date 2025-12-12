/** @type {import('tailwindcss').Config} */
module.exports = {
	content: ['./src/**/*.{svelte,ts}'],
	darkMode: 'class',
	theme: {
		extend: {
			colors: {
				bg: '#f8f8fb',
				card: '#ffffff',
				input: '#f4f4f8',
				text: '#1f1b2a',
				muted: '#6f667d',
				accent: '#50485c',
				accentHover: '#6a5f74',
				error: '#cc4b6a',
				success: '#3c9c7b',
				warning: '#c59b2a',
				borderc: '#d8d6e2'
			},
			borderRadius: {
				DEFAULT: '10px'
			},
			boxShadow: {
				card: '0 18px 60px rgba(0,0,0,0.35)',
				button: '0 10px 30px rgba(0,0,0,0.25)'
			},
			fontFamily: {
				sans: ['"Open Sans"', 'sans-serif']
			}
		}
	},
	plugins: []
};

