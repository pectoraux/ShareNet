/**
 * TrustBadge — small inline "Verified connection" pill with a shield icon.
 *
 * Used in the hero (under the action button) and could be reused on other
 * screens to reinforce the privacy / integrity posture. Purely presentational
 * — no client hooks, no state. Server-component safe.
 *
 * Task ID: UI-SHELL-HOME
 */

import { Shield } from 'lucide-react';

import { cn } from '@/lib/utils';

export interface TrustBadgeProps {
  /** Visible text. Defaults to "Verified connection". */
  label?: string;
  /** Override the icon. Defaults to a shield outline. */
  icon?: React.ComponentType<{ className?: string }>;
  className?: string;
}

export function TrustBadge({
  label = 'Verified connection',
  icon: Icon = Shield,
  className,
}: TrustBadgeProps) {
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-medium',
        'border border-[color:var(--sn-connected-soft)]',
        'bg-[color:var(--sn-connected-soft)] text-[color:var(--sn-connected-text)]',
        className,
      )}
    >
      <Icon className="size-3.5" aria-hidden />
      {label}
    </span>
  );
}

export default TrustBadge;
