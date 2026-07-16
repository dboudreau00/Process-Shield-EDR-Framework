using System.IO;
using System.Windows;
using ProcessShield.Gui.Services;
using ProcessShield.Gui.ViewModels;

namespace ProcessShield.Gui;

public partial class MainWindow : Window
{
    private readonly MainViewModel _vm;

    public MainWindow()
    {
        InitializeComponent();
        string configPath = Path.Combine(AppContext.BaseDirectory, "shield.config.json");
        _vm = new MainViewModel(configPath);
        DataContext = _vm;

        Loaded += (_, _) =>
        {
            try { _vm.Start(); }
            catch (Exception ex) { AppLog.Error("window start", ex); }
        };
        Closed += (_, _) =>
        {
            try { _vm.Dispose(); }
            catch (Exception ex) { AppLog.Error("window close", ex); }
        };
    }
}
