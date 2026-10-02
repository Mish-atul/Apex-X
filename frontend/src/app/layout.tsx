"use client";

import "./globals.css";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { Shield, LogOut, User, Menu, X } from "lucide-react";
import { useAuth } from "@/hooks/useAuth";
import { useEffect } from "react";

import Header from "@/components/Header";
import { FeedbackProvider } from "@/components/Feedback";
import { pingAPI } from "@/services/api";

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  const pathname = usePathname();
  const router = useRouter();
  const { isAuthenticated, username, loadFromStorage, logout } = useAuth();
  const isLoginPage = pathname === "/login";

  useEffect(() => {
    loadFromStorage();
  }, [loadFromStorage]);

  useEffect(() => {
    // Ping the backend every 60 seconds to prevent it from going to sleep
    pingAPI();
    const interval = setInterval(pingAPI, 60 * 1000);
    return () => clearInterval(interval);
  }, []);







  return (
    <html
      lang="en"
      className="h-full antialiased"
      suppressHydrationWarning
    >
      <head>
        <title>APEX-X — Android Security Analysis</title>
        <meta name="description" content="Analyze Android apps for security vulnerabilities, malware, and privacy risks." />
      </head>
      <body className="min-h-full flex flex-col bg-canvas text-text font-sans relative overflow-x-hidden">
        {/* Northern Lights Background */}
        <div className="fixed inset-0 z-[-1] overflow-hidden pointer-events-none opacity-40 mix-blend-screen">
          <div className="absolute top-[-10%] left-[-10%] w-[50vw] h-[50vh] aurora-blob-1 rounded-full blur-[120px]" />
          <div className="absolute top-[40%] right-[-10%] w-[60vw] h-[60vh] aurora-blob-2 rounded-full blur-[140px]" />
          <div className="absolute bottom-[-20%] left-[20%] w-[70vw] h-[50vh] aurora-blob-3 rounded-full blur-[130px]" />
        </div>

        <FeedbackProvider>
          {/* Navigation */}
          <Header />

          {/* Main Content */}
          <div className="flex-1 flex flex-col relative pt-20">{children}</div>
        </FeedbackProvider>
      </body>
    </html>
  );
}
