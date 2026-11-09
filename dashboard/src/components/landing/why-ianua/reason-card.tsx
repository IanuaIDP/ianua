type ReasonCardProps = {
  description: string;
  number: string;
  title: string;
};

export function ReasonCard({ description, number, title }: ReasonCardProps) {
  return (
    <article className="border-l-4 border-primary pl-6 text-left h-fit">
      <div className="text-right font-['Space_Grotesk','Manrope',sans-serif] text-5xl font-bold leading-none text-textGray">
        {number}
      </div>

      <div className="z-10 max-w-sm mt-6">
        <h3 className="font-['Space_Grotesk','Manrope',sans-serif] text-2xl font-bold text-white">
          {title}
        </h3>
        <p className="mt-4 text-base font-light text-textGray">{description}</p>
      </div>
    </article>
  );
}
