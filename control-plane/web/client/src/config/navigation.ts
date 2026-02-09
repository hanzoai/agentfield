import type { NavigationSection } from '@/components/Navigation/types';

export const navigationSections: NavigationSection[] = [
  {
    id: 'overview',
    title: 'Overview',
    items: [
      {
        id: 'dashboard',
        label: 'Dashboard',
        href: '/dashboard',
        icon: 'dashboard',
        description: 'Real-time system overview and operational metrics'
      }
    ]
  },
  {
    id: 'agent-hub',
    title: 'Agent Hub',
    items: [
      {
        id: 'node-overview',
        label: 'Agent Node',
        href: '/nodes',
        icon: 'data-center',
        description: 'Node infrastructure and status'
      },
      {
        id: 'all-reasoners',
        label: 'Reasoners',
        href: '/reasoners/all',
        icon: 'function',
        description: 'Browse and manage all reasoners'
      }
    ]
  },
  {
    id: 'executions',
    title: 'Executions',
    items: [
      {
        id: 'individual-executions',
        label: 'Individual Executions',
        href: '/executions',
        icon: 'run',
        description: 'Single agent executions and calls'
      },
      {
        id: 'workflow-executions',
        label: 'Workflow Executions',
        href: '/workflows',
        icon: 'flow-data',
        description: 'Multi-step workflow processes'
      }
    ]
  },
  {
    id: 'identity-trust',
    title: 'Identity & Trust',
    items: [
      {
        id: 'did-explorer',
        label: 'DID Explorer',
        href: '/identity/dids',
        icon: 'identification',
        description: 'Explore decentralized identifiers for agents and reasoners'
      },
      {
        id: 'credentials',
        label: 'Credentials',
        href: '/identity/credentials',
        icon: 'shield-check',
        description: 'View and verify execution credentials'
      }
    ]
  },
  {
    id: 'permissions',
    title: 'Permissions',
    items: [
      {
        id: 'pending-permissions',
        label: 'Pending Approvals',
        href: '/permissions/pending',
        icon: 'hourglass',
        description: 'Review and approve pending agent permission requests'
      },
      {
        id: 'permission-history',
        label: 'Permission History',
        href: '/permissions/history',
        icon: 'history',
        description: 'Audit trail of all permission decisions'
      },
      {
        id: 'protected-agents',
        label: 'Protected Agents',
        href: '/permissions/protected-agents',
        icon: 'lock',
        description: 'Configure which agents require permission to call'
      },
      {
        id: 'tag-approval',
        label: 'Tag Approvals',
        href: '/permissions/tag-approval',
        icon: 'shield-check',
        description: 'Review and approve agent tag registrations'
      },
      {
        id: 'access-policies',
        label: 'Access Policies',
        href: '/permissions/access-policies',
        icon: 'settings',
        description: 'Manage tag-based access policies for cross-agent calls'
      }
    ]
  },
  {
    id: 'settings',
    title: 'Settings',
    items: [
      {
        id: 'observability-webhook',
        label: 'Observability Webhook',
        href: '/settings/observability-webhook',
        icon: 'settings',
        description: 'Configure external event forwarding'
      }
    ]
  }
];
