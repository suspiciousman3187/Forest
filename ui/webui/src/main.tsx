import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import PreviewFrame from './PreviewFrame';
import './styles.css';

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <PreviewFrame>
      <App />
    </PreviewFrame>
  </React.StrictMode>,
);
