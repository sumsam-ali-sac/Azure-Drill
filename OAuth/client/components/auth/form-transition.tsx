"use client"

import type React from "react"

import { motion } from "framer-motion"

interface FormTransitionProps {
  children: React.ReactNode
  delay?: number
}

export function FormTransition({ children, delay = 0 }: FormTransitionProps) {
  return (
    <motion.div
      initial={{ opacity: 0, x: -20 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{
        duration: 0.4,
        delay,
        ease: [0.4, 0.0, 0.2, 1],
      }}
    >
      {children}
    </motion.div>
  )
}
