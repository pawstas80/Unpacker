namespace Unpacker
{
    internal enum CommandMode
    {
        Extract,
        List,
        Test
    }

    internal enum Verbosity
    {
        Quiet,
        Normal,
        Verbose
    }

    internal sealed class CommandOptions
    {
        public CommandMode Mode { get; set; } = CommandMode.Extract;

        public Verbosity Verbosity { get; set; } = Verbosity.Normal;

        public bool Recursive { get; set; }

        public int MaxDepth { get; set; } = 3;

        public bool NoLog { get; set; }

        public string LogPath { get; set; }

        public string InputFile { get; set; }

        public string OutputDirectory { get; set; }
    }
}
