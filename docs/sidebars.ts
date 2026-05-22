import type { SidebarsConfig } from '@docusaurus/plugin-content-docs';

const sidebars: SidebarsConfig = {
    docsSidebar: [
        'intro',
        {
            type: 'category',
            label: 'Getting started',
            collapsed: false,
            items: [
                'install',
                'quickstart-rust',
                'quickstart-cli',
            ],
        },
        {
            type: 'category',
            label: 'Reference',
            items: [
                'specification',
                'ap-deobfuscation',
            ],
        },
        {
            type: 'category',
            label: 'Related',
            items: [
                'openqbw',
            ],
        },
    ],
};

export default sidebars;
