import { useEffect } from "react";
import "./Toast.css";

interface ToastProps {
  message: string;
  toastState: boolean;
  setToastState: (a: boolean) => void;
}

export function Toast({ message, toastState, setToastState }: ToastProps) {
  useEffect(() => {
    let timer = setTimeout(() => {
      setToastState(false); // 2초 뒤, toastState가 false가 되면서 알림창이 사라진다
    }, 2000);

    return () => {
      clearTimeout(timer);
    };
  }, []);

  return (
    <div
      style={{
        position: "absolute",
        top: 4,
        right: -200,
      }}
      className="alert"
    >
      {message}
    </div>
  );
}
