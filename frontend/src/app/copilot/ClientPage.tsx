"use client";

import { useState, useRef, useEffect } from "react";
import { Send, Cpu, Loader2, Zap, ArrowLeft } from "lucide-react";
import Link from "next/link";
import CopilotSidebar from "./CopilotSidebar";
import { getCases, CaseResponse } from "@/services/api";

interface Message {
  id: string;
  role: "system" | "user" | "ai";
  content: string;
}

export default function CoPilotPage() {
  const [messages, setMessages] = useState<Message[]>([
    {
      id: "system-init",
      role: "system",
      content:
        "APEX-X Co-Pilot initialized — powered by Qwen 2.5 (Local LLM). Select a case and ask me anything about its security analysis.",
    },
  ]);
  const [input, setInput] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  
  const [cases, setCases] = useState<CaseResponse[]>([]);
  const [selectedCase, setSelectedCase] = useState("");

  useEffect(() => {
    async function loadCases() {
      const res = await getCases();
      if (res.data) {
        setCases(res.data);
        if (res.data.length > 0 && !selectedCase) {
          setSelectedCase(res.data[0].id);
        }
      }
    }
    loadCases();
  }, [selectedCase]);

  // Build context for the selected case
  // Builds COMPLETE context for the selected case — zero truncation.
  // The AI must know everything the analyst sees on screen.

  const handleSend = async (e?: React.FormEvent) => {
    e?.preventDefault();
    const userMessage = input.trim();
    if (!userMessage || isLoading) return;

    setMessages((prev) => [...prev, { id: crypto.randomUUID(), role: "user", content: userMessage }]);
    setInput("");
    setIsLoading(true);

    try {
      // Build conversation history for context
      const history = messages
        .filter((m) => m.role === "user" || m.role === "ai")
        .slice(-6) // last 3 exchanges
        .map((m) => ({
          role: m.role === "ai" ? "assistant" : "user",
          content: m.content,
        }));

      const apiUrl = process.env.NEXT_PUBLIC_API_URL || "/api/v1";
      const res = await fetch(`${apiUrl}/copilot`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          message: userMessage,
          case_id: selectedCase,
          history,
        }),
      });

      const data = await res.json();

      if (res.ok && data.message) {
        setMessages((prev) => [
          ...prev,
          { id: crypto.randomUUID(), role: "ai", content: data.message },
        ]);
      } else {
        setMessages((prev) => [
          ...prev,
          {
            id: crypto.randomUUID(),
            role: "ai",
            content: `⚠️ Error: ${data.detail || data.error || "Failed to get AI response"}. Make sure Ollama is running with: ollama serve`,
          },
        ]);
      }
    } catch {
      setMessages((prev) => [
        ...prev,
        {
          id: crypto.randomUUID(),
          role: "ai",
          content:
            "⚠️ Network error — could not reach the AI service. Please check your connection.",
        },
      ]);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  return (
    <main className="flex-1 flex flex-col md:flex-row max-w-7xl mx-auto w-full p-4 md:p-6 gap-4 md:gap-6 h-[calc(100vh-70px)]">
      {/* Sidebar */}
      <CopilotSidebar
        selectedCase={selectedCase}
        setSelectedCase={setSelectedCase}
        setInput={setInput}
        cases={cases}
      />

      {/* Main Chat Area */}
      <div className="flex-1 bg-panel border border-border-subtle flex flex-col min-h-0 relative">
        {/* Chat History */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {messages.map((msg) => (
            <div
              key={msg.id}
              className={`flex gap-4 max-w-[85%] ${
                msg.role === "user" ? "ml-auto flex-row-reverse" : ""
              }`}
            >
              {/* Avatar */}
              <div className="shrink-0 mt-1">
                {msg.role === "system" || msg.role === "ai" ? (
                  <div className="w-8 h-8 bg-primary text-white flex items-center justify-center">
                    <Cpu className="w-5 h-5" />
                  </div>
                ) : (
                  <div className="w-8 h-8 bg-canvas border border-border-subtle flex items-center justify-center">
                    <span className="text-xs font-mono font-bold">YOU</span>
                  </div>
                )}
              </div>

              {/* Message Bubble */}
              <div
                className={`p-4 text-sm leading-relaxed ${
                  msg.role === "user"
                    ? "bg-canvas border border-border-subtle text-primary"
                    : msg.role === "system"
                    ? "bg-primary text-white"
                    : "bg-white border border-border-subtle shadow-sm"
                }`}
              >
                <div className="whitespace-pre-wrap">{msg.content}</div>
              </div>
            </div>
          ))}

          {/* Loading indicator */}
          {isLoading && (
            <div className="flex gap-4 max-w-[85%]">
              <div className="shrink-0 mt-1">
                <div className="w-8 h-8 bg-primary text-white flex items-center justify-center">
                  <Cpu className="w-5 h-5" />
                </div>
              </div>
              <div className="p-4 bg-white border border-border-subtle shadow-sm text-sm">
                <div className="flex items-center gap-2 text-primary/60">
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span className="font-mono text-xs">
                    Qwen 2.5 is reasoning...
                  </span>
                </div>
              </div>
            </div>
          )}

          <div ref={messagesEndRef} />
        </div>

        {/* Input Area */}
        <div className="p-4 bg-canvas border-t border-border-subtle">
          <form onSubmit={handleSend} className="flex gap-2">
            <input
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="Ask Co-Pilot about the case..."
              aria-label="Ask Co-Pilot about the case"
              disabled={isLoading}
              className="flex-1 bg-white border border-border-subtle px-4 py-3 text-sm focus:outline-none focus:border-primary/50 disabled:opacity-50"
            />
            <button
              type="submit"
              disabled={!input.trim() || isLoading}
              className="bg-primary text-white px-6 flex items-center justify-center hover:bg-primary/90 disabled:opacity-50 transition-colors"
            >
              <Send className="w-4 h-4" />
            </button>
          </form>
          <div className="text-center mt-2">
            <span className="text-[10px] font-mono text-primary/40 uppercase">
              Powered by Qwen 2.5 (Local) · All inference runs locally via Ollama — zero cloud API calls.
            </span>
          </div>
        </div>
      </div>
    </main>
  );
}
