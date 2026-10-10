import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import { SymbolRenameProvider } from './context/SymbolRenameContext';
import './index.css';

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <SymbolRenameProvider>
      <App />
    </SymbolRenameProvider>
  </React.StrictMode>
);
