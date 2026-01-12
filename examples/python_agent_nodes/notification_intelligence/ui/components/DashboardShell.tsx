'use client'

import React from 'react'

function cn(...classes: (string | undefined | false)[]) {
  return classes.filter(Boolean).join(' ')
}

interface DashboardShellProps extends React.HTMLAttributes<HTMLDivElement> {
  children: React.ReactNode
}

export function DashboardShell({ children, className, ...props }: DashboardShellProps) {
  return (
    <div
      className={cn(
        'flex flex-col h-screen overflow-hidden bg-zinc-950 text-zinc-100 font-sans',
        className
      )}
      {...props}
    >
      {children}
    </div>
  )
}

interface DashboardHeaderProps extends React.HTMLAttributes<HTMLElement> {
  children: React.ReactNode
}

export function DashboardHeader({ children, className, ...props }: DashboardHeaderProps) {
  return (
    <header
      className={cn(
        'h-14 border-b border-zinc-800 flex items-center justify-between px-6 bg-zinc-950/95 backdrop-blur supports-[backdrop-filter]:bg-zinc-950/60 shrink-0 z-10',
        className
      )}
      {...props}
    >
      {children}
    </header>
  )
}

interface DashboardMainProps extends React.HTMLAttributes<HTMLDivElement> {
  children: React.ReactNode
}

export function DashboardMain({ children, className, ...props }: DashboardMainProps) {
  return (
    <main className={cn('flex-1 flex overflow-hidden', className)} {...props}>
      {children}
    </main>
  )
}
