import type {
  ButtonHTMLAttributes,
} from "react";


type ButtonProps =
  ButtonHTMLAttributes<HTMLButtonElement>;


export function Button({
  className = "",
  children,
  ...props
}: ButtonProps) {
  return (
    <button
      className={`button ${className}`}
      {...props}
    >
      {children}
    </button>
  );
}