import React from "react";
import { VisibilityContext } from "react-horizontal-scrolling-menu";
import "react-horizontal-scrolling-menu/dist/styles.css";
import styled from "styled-components";
import KeyboardDoubleArrowLeftIcon from "@mui/icons-material/KeyboardDoubleArrowLeft";
import KeyboardDoubleArrowRightIcon from "@mui/icons-material/KeyboardDoubleArrowRight";

function Arrow({
  children,
  disabled,
  onClick,
}: {
  children: React.ReactNode;
  disabled: boolean;
  onClick: VoidFunction;
}) {
  return (
    <Button
      disabled={disabled}
      onClick={onClick}
      style={{
        cursor: "pointer",
        display: "flex",
        flexDirection: "column",
        justifyContent: "center",
        right: "1%",
        opacity: disabled ? "0" : "1",
        userSelect: "none",
      }}
    >
      {children}
    </Button>
  );
}

const Button = styled.button`
  cursor: pointer;
  color: #167bff;
  z-index: 999;
  background-color: inherit;
  border: none;
`;

export function LeftArrow() {
  const { isFirstItemVisible, scrollPrev } =
    React.useContext(VisibilityContext);

  return isFirstItemVisible ? (
    <></>
  ) : (
    <Arrow disabled={isFirstItemVisible} onClick={() => scrollPrev()}>
      <KeyboardDoubleArrowLeftIcon />
    </Arrow>
  );
}

export function RightArrow() {
  const { isLastItemVisible, scrollNext } = React.useContext(VisibilityContext);

  return isLastItemVisible ? (
    <></>
  ) : (
    <Arrow disabled={isLastItemVisible} onClick={() => scrollNext()}>
      <KeyboardDoubleArrowRightIcon />
    </Arrow>
  );
}
