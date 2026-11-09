// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import starlightLinksValidator from 'starlight-links-validator';
import mermaid from 'astro-mermaid';

export default defineConfig({
	site: 'https://ianuaidp.github.io',
	base: '/ianua',
	integrations: [
		mermaid({
			theme: 'base',
			autoTheme: false,
			mermaidConfig: {
				flowchart: {
					curve: 'basis',
					padding: 18,
					nodeSpacing: 48,
					rankSpacing: 56,
					wrappingWidth: 320,
				},
				themeVariables: {
					fontFamily:
						'ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
					fontSize: '15px',
				},
			},
		}),
		starlight({
			title: 'Ianua',
			description: 'An access control plane with governed automation, for people and AI agents.',
			social: [{ icon: 'github', label: 'GitHub', href: 'https://github.com/IanuaIDP/ianua' }],
			editLink: { baseUrl: 'https://github.com/IanuaIDP/ianua/edit/main/docs/' },
			lastUpdated: true,
			customCss: ['./src/styles/diagrams.css'],
			plugins: [starlightLinksValidator()],
			sidebar: [
				{ label: 'Start here', items: [{ autogenerate: { directory: 'start' } }] },
				{ label: 'Concepts', items: [{ autogenerate: { directory: 'concepts' } }] },
				{
					label: 'Guides',
					items: [
						{
							label: 'Organizations and tenants',
							collapsed: true,
							items: [{ autogenerate: { directory: 'guides/organizations-and-tenants' } }],
						},
						{
							label: 'People and access',
							collapsed: true,
							items: [{ autogenerate: { directory: 'guides/people-and-access' } }],
						},
						{
							label: 'Apps',
							collapsed: true,
							items: [{ autogenerate: { directory: 'guides/apps' } }],
						},
						{
							label: 'Keys and connections',
							collapsed: true,
							items: [{ autogenerate: { directory: 'guides/keys-and-connections' } }],
						},
						{
							label: 'Agents',
							collapsed: true,
							items: [{ autogenerate: { directory: 'guides/agents' } }],
						},
						{
							label: 'Automation',
							collapsed: true,
							items: [{ autogenerate: { directory: 'guides/automation' } }],
						},
						{
							label: 'Settings',
							collapsed: true,
							items: [{ autogenerate: { directory: 'guides/settings' } }],
						},
					],
				},
				{ label: 'Architecture', items: [{ autogenerate: { directory: 'architecture' } }] },
				{ label: 'Domain contexts', items: [{ autogenerate: { directory: 'domain-contexts' } }] },
				{ label: 'Code design', items: [{ autogenerate: { directory: 'code-design' } }] },
				{
					label: 'Dashboard',
					items: [
						{ autogenerate: { directory: 'dashboard', collapsed: false } },
					],
				},
				{ label: 'Reference', items: [{ autogenerate: { directory: 'reference' } }] },
				{ label: 'Security', items: [{ autogenerate: { directory: 'security' } }] },
				{ label: 'Contributing', items: [{ autogenerate: { directory: 'contributing' } }] },
			],
		}),
	],
});
