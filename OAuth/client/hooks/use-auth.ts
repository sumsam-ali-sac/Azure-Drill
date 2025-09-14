"use client"

import { useState, useEffect, useCallback } from "react"
import { AuthService } from "@/lib/auth"
import type { User, LoginCredentials, SignupCredentials } from "@/types/auth"

export function useAuth() {
  const [user, setUser] = useState<User | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [isAuthenticated, setIsAuthenticated] = useState(false)

  const authService = AuthService.getInstance()

  // Initialize auth state
  useEffect(() => {
    const initAuth = async () => {
      try {
        const currentUser = await authService.getCurrentUser()
        if (currentUser) {
          setUser(currentUser)
          setIsAuthenticated(true)
        }
      } catch (error) {
        console.error("Failed to initialize auth:", error)
      } finally {
        setIsLoading(false)
      }
    }

    initAuth()
  }, [])

  const login = useCallback(async (credentials: LoginCredentials) => {
    setIsLoading(true)
    try {
      const { user } = await authService.login(credentials)
      setUser(user)
      setIsAuthenticated(true)
      return { success: true, user }
    } catch (error) {
      console.error("Login failed:", error)
      return {
        success: false,
        error: error instanceof Error ? error.message : "Login failed",
      }
    } finally {
      setIsLoading(false)
    }
  }, [])

  const signup = useCallback(async (credentials: SignupCredentials) => {
    setIsLoading(true)
    try {
      const { user } = await authService.signup(credentials)
      setUser(user)
      setIsAuthenticated(true)
      return { success: true, user }
    } catch (error) {
      console.error("Signup failed:", error)
      return {
        success: false,
        error: error instanceof Error ? error.message : "Signup failed",
      }
    } finally {
      setIsLoading(false)
    }
  }, [])

  const socialLogin = useCallback(async (provider: "google" | "azure") => {
    setIsLoading(true)
    try {
      const { user } = await authService.socialLogin(provider)
      setUser(user)
      setIsAuthenticated(true)
      return { success: true, user }
    } catch (error) {
      console.error("Social login failed:", error)
      return {
        success: false,
        error: error instanceof Error ? error.message : "Social login failed",
      }
    } finally {
      setIsLoading(false)
    }
  }, [])

  const logout = useCallback(async () => {
    setIsLoading(true)
    try {
      await authService.logout()
      setUser(null)
      setIsAuthenticated(false)
      return { success: true }
    } catch (error) {
      console.error("Logout failed:", error)
      return {
        success: false,
        error: error instanceof Error ? error.message : "Logout failed",
      }
    } finally {
      setIsLoading(false)
    }
  }, [])

  const refreshAuth = useCallback(async () => {
    try {
      return await authService.refreshToken()
    } catch (error) {
      console.error("Token refresh failed:", error)
      return false
    }
  }, [])

  const hasPermission = useCallback((permission: string) => authService.hasPermission(permission), [user])

  const isAdmin = useCallback(() => authService.isAdmin(), [user])

  return {
    user,
    isLoading,
    isAuthenticated,
    login,
    signup,
    socialLogin,
    logout,
    refreshAuth,
    hasPermission,
    isAdmin,
  }
}
