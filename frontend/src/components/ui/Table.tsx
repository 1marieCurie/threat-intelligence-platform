import type {
  ReactNode,
} from "react";


type TableProps = {
  children: ReactNode;
  className?: string;
};


export function Table({
  children,
  className = "",
}: TableProps) {
  return (
    <div
      className={
        `table-container ${className}`
      }
    >
      <table className="data-table">
        {children}
      </table>
    </div>
  );
}