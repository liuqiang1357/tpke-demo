import { cx } from 'class-variance-authority';
import { ClassValue } from 'class-variance-authority/types';
import { DefaultClassGroupIds, extendTailwindMerge } from 'tailwind-merge';

const tailwindMerge = extendTailwindMerge({
  extend: {
    conflictingClassGroups: {
      ['arbitrary..text-align' as DefaultClassGroupIds]: ['text-alignment'],
      'text-alignment': ['arbitrary..text-align' as DefaultClassGroupIds],
    },
  },
});

export function cn(...inputs: ClassValue[]) {
  return tailwindMerge(cx(inputs));
}
