import Image from "next/image";

import Link from "next/link"; // Import Link from Next.js
interface LogoProps {
  width: number;
  height: number;
}
export default function Logo({ width, height }: LogoProps) {
  return (
    <Link href="/">
      <Image
        src={"/nebra.svg"}
        alt="Nebra Logo"
        width={width}
        height={height}
        draggable={false}
        className="rounded-xl"
      />
    </Link>
  );
}
