import React, { useState } from 'react';
import { NavLink } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { Sun, Moon, Search, Bell, Settings, ChevronLeft, ChevronRight } from 'lucide-react';
import { cn } from '../../lib/utils';
import { useTheme } from '../../contexts/ThemeContext';

const Layout = ({ children }) => {
  const [isSidebarOpen, setIsSidebarOpen] = useState(true);
  const { isDarkMode, toggleTheme } = useTheme();

  const toggleSidebar = () => setIsSidebarOpen(!isSidebarOpen);

  return (
    <div className={cn(
      "min-h-screen bg-background text-foreground",
      isDarkMode ? "dark" : ""
    )}>
      {/* Navbar */}
      <nav className="fixed top-0 left-0 right-0 h-16 bg-card border-b border-border z-50">
        <div className="flex items-center justify-between h-full px-4">
          <div className="flex items-center space-x-4">
            <button
              onClick={toggleSidebar}
              className="p-2 rounded-lg hover:bg-neutral-100 dark:hover:bg-neutral-800 transition-colors"
            >
              {isSidebarOpen ? <ChevronLeft size={20} /> : <ChevronRight size={20} />}
            </button>
            <h1 className="text-xl font-semibold">Security Scanner</h1>
          </div>
          
          <div className="flex items-center space-x-2">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-neutral-400" size={18} />
              <input
                type="text"
                placeholder="Search..."
                className="pl-10 pr-4 py-2 rounded-lg bg-neutral-100 dark:bg-neutral-800 border border-transparent focus:border-primary-500 focus:outline-none"
              />
            </div>
            
            <button
              onClick={toggleTheme}
              className="p-2 rounded-lg hover:bg-neutral-100 dark:hover:bg-neutral-800 transition-colors"
            >
              {isDarkMode ? <Sun size={20} /> : <Moon size={20} />}
            </button>
            
            <button className="p-2 rounded-lg hover:bg-neutral-100 dark:hover:bg-neutral-800 transition-colors">
              <Bell size={20} />
            </button>
            
            <button className="p-2 rounded-lg hover:bg-neutral-100 dark:hover:bg-neutral-800 transition-colors">
              <Settings size={20} />
            </button>
          </div>
        </div>
      </nav>

      {/* Sidebar */}
      <AnimatePresence>
        {isSidebarOpen && (
          <motion.aside
            initial={{ x: -300 }}
            animate={{ x: 0 }}
            exit={{ x: -300 }}
            transition={{ type: "spring", damping: 20 }}
            className="fixed top-16 left-0 h-[calc(100vh-4rem)] w-64 bg-card border-r border-border"
          >
            <nav className="p-4 space-y-2">
              <NavLink to="/dashboard" className={({ isActive }) =>
                cn("flex items-center space-x-3 p-2 rounded-lg transition-colors",
                   isActive ? "bg-primary-100 dark:bg-primary-900 text-primary-900 dark:text-primary-100" : "hover:bg-neutral-100 dark:hover:bg-neutral-800")}
              >
                <span>Dashboard</span>
              </NavLink>
              <NavLink to="/scans" className={({ isActive }) =>
                cn("flex items-center space-x-3 p-2 rounded-lg transition-colors",
                   isActive ? "bg-primary-100 dark:bg-primary-900 text-primary-900 dark:text-primary-100" : "hover:bg-neutral-100 dark:hover:bg-neutral-800")}
              >
                <span>Scans</span>
              </NavLink>
              <NavLink to="/reports" className={({ isActive }) =>
                cn("flex items-center space-x-3 p-2 rounded-lg transition-colors",
                   isActive ? "bg-primary-100 dark:bg-primary-900 text-primary-900 dark:text-primary-100" : "hover:bg-neutral-100 dark:hover:bg-neutral-800")}
              >
                <span>Reports</span>
              </NavLink>
              <NavLink to="/settings" className={({ isActive }) =>
                cn("flex items-center space-x-3 p-2 rounded-lg transition-colors",
                   isActive ? "bg-primary-100 dark:bg-primary-900 text-primary-900 dark:text-primary-100" : "hover:bg-neutral-100 dark:hover:bg-neutral-800")}
              >
                <span>Settings</span>
              </NavLink>
            </nav>
          </motion.aside>
        )}
      </AnimatePresence>

      {/* Main Content */}
      <main className={cn(
        "pt-16 min-h-screen transition-all duration-300",
        isSidebarOpen ? "pl-64" : "pl-0"
      )}>
        <div className="container mx-auto p-6">
          {children}
        </div>
      </main>
    </div>
  );
};

export default Layout; 