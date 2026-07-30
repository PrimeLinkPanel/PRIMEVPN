import * as React from 'react'
import * as LabelPrimitive from '@radiprimevpn/react-label'
import { cva } from 'class-variance-authority';
import type { VariantProps } from 'class-variance-authority';

import { cn } from '@/pg-ui/lib/utils';

const labelVariants = cva('text-sm font-medium leading-snug peer-disabled:cursor-not-allowed peer-disabled:opacity-70')

const Label = React.forwardRef<React.ElementRef<typeof LabelPrimitive.Root>, React.ComponentPropsWithoutRef<typeof LabelPrimitive.Root> & VariantProps<typeof labelVariants>>(
  ({ className, ...props }, ref) => <LabelPrimitive.Root ref={ref} className={cn(labelVariants(), className)} {...props} />,
)
Label.displayName = LabelPrimitive.Root.displayName

export { Label }
