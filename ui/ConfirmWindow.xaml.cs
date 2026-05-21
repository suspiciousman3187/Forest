using System.Windows;
using MahApps.Metro.Controls;

namespace Forest.UI;

public partial class ConfirmWindow : MetroWindow
{
    private ConfirmWindow(string message, string confirmText, bool danger,
                          string header, bool okOnly)
    {
        InitializeComponent();
        MsgText.Text = message;
        HeaderText.Text = header;
        ConfirmBtn.Content = confirmText;
        if (danger)
            ConfirmBtn.Style = (Style)FindResource("BarDanger");
        if (okOnly)
        {

            CancelBtn.Visibility = Visibility.Collapsed;
            System.Windows.Controls.Grid.SetColumn(ConfirmBtn, 0);
            System.Windows.Controls.Grid.SetColumnSpan(ConfirmBtn, 3);
        }
    }

    private void OnCancel(object s, RoutedEventArgs e)  => DialogResult = false;
    private void OnConfirm(object s, RoutedEventArgs e) => DialogResult = true;

    public static bool Ask(Window owner, string message,
                           string confirmText = "Confirm", bool danger = false,
                           string header = "CONFIRM")
    {
        var w = new ConfirmWindow(message, confirmText, danger, header,
                                  okOnly: false) { Owner = owner };
        return w.ShowDialog() == true;
    }

    public static void Info(Window owner, string message,
                            string header = "NOTICE")
    {
        new ConfirmWindow(message, "OK", danger: false, header,
                          okOnly: true) { Owner = owner }.ShowDialog();
    }
}
