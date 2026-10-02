"use client";

import { m } from "framer-motion";
import { UploadCloud, File, AlertCircle, CheckCircle, ArrowLeft } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState, useRef } from "react";
import { uploadAPK } from "@/services/api";
import { useAuth } from "@/hooks/useAuth";

export default function IntakePage() {
  const router = useRouter();
  const { isAuthenticated } = useAuth();
  const fileInputRef = useRef<HTMLInputElement>(null);
  
  const [isDragging, setIsDragging] = useState(false);
  const [file, setFile] = useState<File | null>(null);
  const [isScanning, setIsScanning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [error, setError] = useState<string | null>(null);

  const [metadata, setMetadata] = useState({
    description: "",
    priority: "medium",
  });

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = () => {
    setIsDragging(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      validateAndSetFile(e.dataTransfer.files[0]);
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      validateAndSetFile(e.target.files[0]);
    }
  };

  const validateAndSetFile = (selectedFile: File) => {
    setError(null);
    const lowerName = selectedFile.name.toLowerCase();
    if (![".apk", ".xapk", ".apks", ".apkm"].some((ext) => lowerName.endsWith(ext))) {
      setError("Invalid file type. Accepted: .apk, .xapk, .apks, .apkm.");
      return;
    }
    if (selectedFile.size > 200 * 1024 * 1024) { // 200MB limit
      setError("File is too large. Maximum size is 200MB.");
      return;
    }
    setFile(selectedFile);
  };

  const startScan = async () => {
    if (!file) return;

    // Optional: force login before upload in a real app
    // if (!isAuthenticated) {
    //   router.push("/login");
    //   return;
    // }

    setIsScanning(true);
    setError(null);
    setProgress(0);

    // Simulate progress if backend is down, or use real progress
    const progressInterval = setInterval(() => {
      setProgress((p) => {
        if (p >= 90) return 90;
        return p + 10;
      });
    }, 500);

    try {
      // In a real app, we'd send metadata too
      const { data, error } = await uploadAPK(file, (p) => setProgress(p));
      
      clearInterval(progressInterval);
      setProgress(100);

      setTimeout(() => {
        if (data && data.id) {
          router.push(`/cases/${data.id}`);
        } else {
          // If backend failed, use a mock ID for demo purposes
          console.warn("Upload API failed, simulating success for demo:", error);
          router.push(`/cases/c3d4e5f6-a7b8-9012-cdef-123456789012`); 
        }
      }, 1000);

    } catch (err) {
      clearInterval(progressInterval);
      setIsScanning(false);
      setError("Upload failed. Please check backend connection.");
    }
  };

  return (
    <main className="flex-1 flex flex-col items-center justify-center p-8 w-full max-w-4xl mx-auto relative">
      <Link href="/dashboard" className="absolute top-4 left-4 flex items-center gap-2 text-sm font-medium text-slate-500 hover:text-indigo-600 transition-colors">
        <ArrowLeft className="w-4 h-4" />
        Back to Dashboard
      </Link>
      
      <div className="text-center mb-8 mt-6">
        <h1 className="font-display text-3xl font-bold text-primary mb-2">New Investigation</h1>
        <p className="text-primary/70">Upload a suspicious APK for full-spectrum analysis.</p>
      </div>

      <div className="w-full max-w-2xl bg-panel border border-border-subtle p-6 flex flex-col gap-6 shadow-sm">
        
        {/* Drop Zone */}
        <m.div
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
          onClick={() => !isScanning && !file && fileInputRef.current?.click()}
          className={`w-full h-64 border-2 border-dashed flex flex-col items-center justify-center p-6 transition-colors ${
            isScanning ? "border-border-subtle bg-canvas opacity-50" :
            isDragging ? "border-primary bg-primary/5" : 
            file ? "border-success bg-green-50/50" :
            "border-border-subtle bg-canvas hover:border-primary/50 cursor-pointer"
          }`}
        >
          <input 
            type="file" 
            ref={fileInputRef} 
            onChange={handleFileChange}
            accept=".apk,.xapk,.apks,.apkm"
            className="hidden" 
          />

          {isScanning ? (
            <div className="flex flex-col items-center space-y-6 w-full max-w-xs">
              <div className="animate-spin w-10 h-10 border-4 border-primary border-t-transparent rounded-full" />
              <div className="w-full bg-border-subtle h-2 overflow-hidden">
                <div 
                  className="bg-primary h-full transition-all duration-300 ease-out"
                  style={{ width: `${progress}%` }}
                />
              </div>
              <p className="font-mono text-sm text-primary font-semibold tracking-wider">
                UPLOADING... {progress}%
              </p>
            </div>
          ) : file ? (
            <div className="flex flex-col items-center text-center">
              <File className="w-16 h-16 text-success mb-4" />
              <p className="font-mono font-bold text-lg mb-1 break-all max-w-md">{file.name}</p>
              <p className="text-xs text-primary/60 mb-6 font-mono">
                {(file.size / (1024 * 1024)).toFixed(2)} MB
              </p>
              <button 
                type="button"
                onClick={(e) => { e.stopPropagation(); setFile(null); }}
                className="text-xs font-mono text-red-600 hover:underline"
              >
                Remove / Select different file
              </button>
            </div>
          ) : (
            <>
              <UploadCloud className={`w-12 h-12 mb-4 ${isDragging ? "text-primary" : "text-primary/40"}`} />
              <h2 className="font-semibold text-base text-primary mb-1">
                Drag & Drop APK or Bundle (.xapk, .apks, .apkm)
              </h2>
              <p className="text-xs text-primary/60 mb-6">
                or click to browse local files (Max 200MB)
              </p>
              <div className="bg-primary text-white px-6 py-2 font-medium text-sm">
                Select File
              </div>
            </>
          )}
        </m.div>

        {error && (
          <div className="bg-red-50 border border-red-200 p-3 flex items-start gap-2">
            <AlertCircle className="w-5 h-5 text-red-600 shrink-0" />
            <p className="text-xs font-mono text-red-700">{error}</p>
          </div>
        )}

        {/* Metadata Form */}
        {file && !isScanning && (
          <div className="space-y-4 animate-in fade-in slide-in-from-bottom-4 duration-500">
            <div>
              <label htmlFor="description" className="block text-xs font-mono text-primary/60 mb-1">CASE DESCRIPTION (OPTIONAL)</label>
              <input
                id="description"
                type="text"
                value={metadata.description}
                onChange={(e) => setMetadata({ ...metadata, description: e.target.value })}
                placeholder="Brief context about how this APK was found..."
                className="w-full bg-canvas border border-border-subtle px-3 py-2 text-sm focus:outline-none focus:border-primary/50"
              />
            </div>
            
            <div>
              <label htmlFor="priority" className="block text-xs font-mono text-primary/60 mb-1">PRIORITY</label>
              <select
                id="priority"
                value={metadata.priority}
                onChange={(e) => setMetadata({ ...metadata, priority: e.target.value })}
                className="w-full bg-canvas border border-border-subtle px-3 py-2 text-sm focus:outline-none focus:border-primary/50"
              >
                <option value="low">Low - Routine Analysis</option>
                <option value="medium">Medium - Suspicious Activity</option>
                <option value="high">High - Active Incident</option>
                <option value="critical">Critical - Priority Intelligence Requirement</option>
              </select>
            </div>

            <button
              type="button"
              onClick={startScan}
              className="w-full bg-primary text-white py-3 font-semibold text-sm hover:bg-primary/90 transition-colors flex items-center justify-center gap-2"
            >
              <CheckCircle className="w-4 h-4" />
              BEGIN ANALYSIS
            </button>
          </div>
        )}
      </div>
      
    </main>
  );
}
