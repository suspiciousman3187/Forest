using System.Windows;
using MahApps.Metro.Controls;
using Forest;

namespace Forest.UI;

public partial class AccountWindow : MetroWindow
{
    private readonly string? _editProfile;

    public AccountWindow(string? editProfile = null)
    {
        InitializeComponent();
        _editProfile = editProfile;
        LauncherBox.SelectedIndex = 0;
        if (editProfile != null)
        {
            HeaderText.Text = "EDIT ACCOUNT";
            ProfileBox.Text = editProfile;
            try
            {
                var a = CredentialStore.Load().GetAccount(editProfile);
                WindowerBox.Text = a.WindowerProfile ?? "";
                SlotBox.Text = a.PolSlot == 0 ? "" : a.PolSlot.ToString();
                ArgsBox.Text = a.LaunchArgs ?? "";
                LauncherBox.SelectedIndex =
                    string.Equals(a.Launcher, "Ashita", StringComparison.OrdinalIgnoreCase) ? 2
                    : string.Equals(a.Launcher, "Windower", StringComparison.OrdinalIgnoreCase) ? 1
                    : 0;
            }
            catch {  }
        }
        UpdateProfileLabel();
    }

    private string? SelectedLauncher() => LauncherBox.SelectedIndex switch
    {
        1 => "Windower",
        2 => "Ashita",
        _ => null,
    };

    private void OnLauncherChanged(object s, RoutedEventArgs e) =>
        UpdateProfileLabel();

    private void UpdateProfileLabel()
    {
        if (ProfileLbl == null) return;
        ProfileLbl.Text = LauncherBox.SelectedIndex switch
        {
            1 => "WINDOWER PROFILE",
            2 => "ASHITA BOOT CONFIG  (.ini filename)",
            _ => "WINDOWER PROFILE  /  ASHITA BOOT .INI",
        };
    }

    private void OnTogglePw(object s, RoutedEventArgs e)
    {
        if (PwEye.IsChecked == true)
        {
            PwReveal.Text = PwBox.Password;
            PwBox.Visibility = Visibility.Collapsed;
            PwReveal.Visibility = Visibility.Visible;
            PwReveal.Focus();
            PwReveal.CaretIndex = PwReveal.Text.Length;
        }
        else
        {
            PwBox.Password = PwReveal.Text;
            PwReveal.Visibility = Visibility.Collapsed;
            PwBox.Visibility = Visibility.Visible;
            PwBox.Focus();
        }
    }

    private string CurrentPassword() =>
        PwEye.IsChecked == true ? PwReveal.Text : PwBox.Password;

    private void OnCancel(object s, RoutedEventArgs e) { DialogResult = false; }

    private void OnSave(object s, RoutedEventArgs e)
    {
        var profile = ProfileBox.Text.Trim();
        var pw = CurrentPassword();
        var totp = string.IsNullOrWhiteSpace(TotpBox.Text) ? null : TotpBox.Text.Trim();
        var windower = string.IsNullOrWhiteSpace(WindowerBox.Text) ? null : WindowerBox.Text.Trim();
        var args = string.IsNullOrWhiteSpace(ArgsBox.Text) ? null : ArgsBox.Text.Trim();
        var launcher = SelectedLauncher();
        int slot = int.TryParse(SlotBox.Text.Trim(), out var sv) ? sv : 0;

        if (string.IsNullOrWhiteSpace(profile)) { Err("Profile name is required."); return; }

        var store = CredentialStore.Load();
        bool isNew = _editProfile is null;
        var accounts = store.Accounts();

        if (isNew && accounts.Count >= 20)
        {
            Err("Account limit reached (20). POL only has 20 member-list "
                + "slots — remove an account before adding another.");
            return;
        }

        bool renaming = !isNew &&
            !profile.Equals(_editProfile, StringComparison.OrdinalIgnoreCase);
        if ((isNew || renaming) && accounts.Any(a =>
                a.Name.Equals(profile, StringComparison.OrdinalIgnoreCase) &&
                !a.Name.Equals(_editProfile, StringComparison.OrdinalIgnoreCase)))
        {
            Err($"An account named \"{profile}\" already exists. "
                + "Please choose a different name.");
            return;
        }

        if (slot != 0)
        {
            if (slot < 1 || slot > 20)
            { Err("POL slot must be between 1 and 20."); return; }

            var clash = accounts.FirstOrDefault(a =>
                a.PolSlot == slot &&
                !a.Name.Equals(_editProfile, StringComparison.OrdinalIgnoreCase));
            if (clash != null)
            {
                Err($"POL slot {slot} is already used by \"{clash.Name}\". "
                    + "Please choose a different slot.");
                return;
            }
        }

        try
        {

            if (renaming && !store.Rename(_editProfile!, profile))
            {
                Err($"Could not rename to \"{profile}\" (name already in use).");
                return;
            }

            if (isNew)
            {
                if (string.IsNullOrEmpty(pw)) { Err("Password is required for a new account."); return; }
                store.Set(profile, pw, totp, windower, slot, args, launcher);
            }
            else if (!string.IsNullOrEmpty(pw))
            {

                store.Set(profile, pw, totp, windower, slot, args, launcher);
            }
            else
            {

                store.SetMeta(profile, windower, slot, args, launcher);
            }
            DialogResult = true;
        }
        catch (Exception ex) { Err(ex.Message); }
    }

    private void Err(string m)
    {
        ErrText.Text = m;
        ErrBanner.Visibility = Visibility.Visible;
    }
}
