import React, { useState } from 'react';
import { Lock, Eye, EyeOff, Loader2 } from 'lucide-react';
import { Logo } from './Icons';

interface LoginPageProps {
  onLogin: () => void;
  language: 'en' | 'zh';
}

// SHA-256 hash of the password (actual password is not stored in code)
const PASSWORD_HASH = '9c372049aa711d201e0f7fb1be0df66ef563503a029e5aa489496796b2aa99e0';

async function hashPassword(password: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(password);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  return hashHex;
}

export function LoginPage({ onLogin, language }: LoginPageProps) {
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState(false);
  const [isLoading, setIsLoading] = useState(false);

  const texts = {
    en: {
      title: 'Welcome to Peinture',
      subtitle: 'Please enter your password to continue',
      placeholder: 'Enter password',
      button: 'Login',
      error: 'Incorrect password, please try again',
    },
    zh: {
      title: '欢迎使用 Peinture',
      subtitle: '请输入密码以继续',
      placeholder: '请输入密码',
      button: '登录',
      error: '密码错误，请重试',
    },
  };

  const t = texts[language];

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!password.trim()) {
      setError(true);
      return;
    }

    setIsLoading(true);
    setError(false);

    try {
      const hash = await hashPassword(password);

      if (hash === PASSWORD_HASH) {
        localStorage.setItem('app_authenticated', 'true');
        onLogin();
      } else {
        setError(true);
        setPassword('');
      }
    } catch (err) {
      console.error('Authentication error:', err);
      setError(true);
      setPassword('');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="relative flex h-screen w-full items-center justify-center overflow-hidden bg-gradient-brilliant">
      {/* Background effect */}
      <div className="absolute inset-0 bg-black/30 backdrop-blur-sm"></div>

      {/* Login card */}
      <div className="relative z-10 w-full max-w-md px-4">
        <div className="bg-black/40 backdrop-blur-xl border border-white/10 rounded-2xl p-8 shadow-2xl shadow-black/50">

          {/* Logo and title */}
          <div className="flex flex-col items-center mb-8">
            <Logo className="size-16 mb-4" />
            <h1 className="text-white text-2xl font-bold mb-2">{t.title}</h1>
            <p className="text-white/60 text-sm text-center">{t.subtitle}</p>
          </div>

          {/* Login form */}
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="relative">
              <div className="absolute inset-y-0 left-0 flex items-center pl-3 pointer-events-none">
                <Lock className="w-5 h-5 text-white/40" />
              </div>

              <input
                type={showPassword ? 'text' : 'password'}
                value={password}
                onChange={(e) => {
                  setPassword(e.target.value);
                  setError(false);
                }}
                placeholder={t.placeholder}
                className="w-full pl-10 pr-10 py-3 bg-white/5 border border-white/10 rounded-lg text-white placeholder-white/40 focus:outline-none focus:ring-2 focus:ring-purple-500/50 focus:border-purple-500/50 transition-all"
                disabled={isLoading}
              />

              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="absolute inset-y-0 right-0 flex items-center pr-3 text-white/40 hover:text-white/60 transition-colors"
                disabled={isLoading}
              >
                {showPassword ? (
                  <EyeOff className="w-5 h-5" />
                ) : (
                  <Eye className="w-5 h-5" />
                )}
              </button>
            </div>

            {error && (
              <div className="text-red-400 text-sm text-center bg-red-500/10 border border-red-500/20 rounded-lg py-2 px-3">
                {t.error}
              </div>
            )}

            <button
              type="submit"
              disabled={isLoading || !password.trim()}
              className="w-full flex items-center justify-center gap-2 py-3 px-4 bg-gradient-to-r from-purple-600 to-pink-600 hover:from-purple-500 hover:to-pink-500 text-white font-semibold rounded-lg transition-all shadow-lg shadow-purple-900/40 hover:shadow-purple-700/50 disabled:opacity-50 disabled:cursor-not-allowed disabled:grayscale"
            >
              {isLoading ? (
                <>
                  <Loader2 className="w-5 h-5 animate-spin" />
                  <span>{t.button}...</span>
                </>
              ) : (
                <span>{t.button}</span>
              )}
            </button>
          </form>
        </div>
      </div>
    </div>
  );
}
