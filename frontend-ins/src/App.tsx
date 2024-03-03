import React from "react";
import "./App.css";
import {
  BrowserRouter as Router,
  Routes,
  Route,
  Navigate,
} from "react-router-dom";
import { Login } from "./pages/Login";
import { AppRoutes } from "./AppRoutes";

function App() {
  return (
    <React.Fragment>
      <Router>
        <Routes>
          {/* 메인페이지없이 */}
          <Route path="/" element={<Navigate replace to="/login" />} />
          {/* 로그인 */}
          <Route path="/login" element={<Login />} />
          {/* 마이페이지 -> 고객 리스트 확인 */}
          <Route path="/*" element={<AppRoutes />} />
        </Routes>
      </Router>
    </React.Fragment>
  );
}

export default App;
