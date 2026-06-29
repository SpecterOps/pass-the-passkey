using System.Text;

namespace SpecterOps.Passkeys.SharpPasskeys;

/// <summary>
/// Renders tabular data as a fixed-width ASCII table with column headers and box-drawing borders.
/// </summary>
internal sealed class AsciiTable
{
    private readonly string[] _headers;
    private readonly List<string[]> _rows = [];

    /// <summary>
    /// Initializes a new table with the specified column headers.
    /// </summary>
    public AsciiTable(params string[] headers)
    {
        _headers = headers;
    }

    /// <summary>
    /// Appends a data row. Values are matched to columns by position.
    /// </summary>
    public void AddRow(params string[] values)
    {
        _rows.Add(values);
    }

    /// <summary>
    /// Writes the formatted table (header, separator, rows) to <paramref name="writer"/>.
    /// Column widths are auto-sized to fit the widest value in each column.
    /// </summary>
    public void Print(TextWriter writer)
    {
        int[] widths = new int[_headers.Length];
        for (int i = 0; i < _headers.Length; i++)
        {
            widths[i] = _headers[i].Length;
        }

        foreach (string[] row in _rows)
        {
            for (int i = 0; i < row.Length && i < widths.Length; i++)
            {
                widths[i] = Math.Max(widths[i], (row[i] ?? string.Empty).Length);
            }
        }

        string separator = BuildSeparator(widths);

        writer.WriteLine(separator);
        WriteRow(writer, _headers, widths);
        writer.WriteLine(separator);

        foreach (string[] row in _rows)
        {
            WriteRow(writer, row, widths);
        }

        writer.WriteLine(separator);
    }

    private static string BuildSeparator(int[] widths)
    {
        var sb = new StringBuilder("+");
        foreach (int w in widths)
        {
            sb.Append('-', w + 2);
            sb.Append('+');
        }

        return sb.ToString();
    }

    private static void WriteRow(TextWriter writer, string[] values, int[] widths)
    {
        writer.Write('|');
        for (int i = 0; i < widths.Length; i++)
        {
            string val = i < values.Length ? (values[i] ?? string.Empty) : string.Empty;
            writer.Write(' ');
            writer.Write(val.PadRight(widths[i]));
            writer.Write(" |");
        }

        writer.WriteLine();
    }
}
