// import "./App.css";
import React from "react";
import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
import { Mypage } from "./pages/Mypage";
import { Container } from "@mui/system";
import { Detail } from "./pages/Detail";
import PrivateRoute from "./components/PrivateRoute";

export function AppRoutes() {
  return (
    <React.Fragment>
      <Container
        fixed
        disableGutters={true}
        maxWidth="lg"
        sx={{ height: "100%" }}
      >
        <Routes>
          <Route element={<PrivateRoute authentication={true} />}>
            <Route path="/mypage" element={<Mypage />} />
          </Route>
          <Route element={<PrivateRoute authentication={true} />}>
            <Route path="/detail/:carId" element={<Detail />} />
          </Route>
        </Routes>
      </Container>
    </React.Fragment>
  );
}
