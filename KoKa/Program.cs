using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using Microsoft.Win32;
using Microsoft.VisualBasic.FileIO;

namespace Koka
{
    sealed class AppInfo
    {
        public string Name, Version, Publisher, Location, Command, DisplayIcon, IconKey;
        public string Type="软件";
        public bool IsInstalled, HasKnownSize, SizeCalculationComplete;
        public long SizeBytes;
        public List<Candidate> Residues = new List<Candidate>();
        public List<DataItem> DataItems = new List<DataItem>();
    }
    sealed class DataItem
    {
        public string Kind, Path, Fingerprint;
        public long Size;
        public Candidate RemovalCandidate;
    }    sealed class Candidate
    {
        public string Path, Key;
        public bool Registry, IsFile;
        public RegistryHive Hive;
        public RegistryView View;
    }
    sealed class SystemEntry
    {
        public string Name, Kind, Path;
        public long Size;
        public bool SizeKnown;
    }
    sealed class DataTreeRow
    {
        public AppInfo App;
        public DataItem Entry;
        public bool IsApp;
    }
    sealed class ResidueEntry
    {
        public string Kind, Path;
        public long Size;
        public Candidate RemovalCandidate;
    }
    sealed class ResidueReport
    {
        public List<ResidueEntry> Entries = new List<ResidueEntry>();
        public int FileCount, FolderCount, RegistryCount;
        public long TotalSizeBytes;
        public bool Complete = true;
    }
    sealed class SizeResult { public long Bytes; public bool Complete = true; }
    sealed class KokaProgressBar : Control
    {
        int value;
        int marqueeOffset;
        bool indeterminate;
        readonly System.Windows.Forms.Timer marqueeTimer;
        public int Minimum { get; set; }
        public int Maximum { get; set; }
        public bool IsIndeterminate
        {
            get { return indeterminate; }
            set { indeterminate=value;if(value){if(!marqueeTimer.Enabled)marqueeTimer.Start();}else marqueeTimer.Stop();Invalidate(); }
        }
        public int Value
        {
            get { return value; }
            set { this.value = Math.Max(Minimum, Math.Min(Maximum, value)); Invalidate(); }
        }
        public KokaProgressBar()
        {
            Minimum = 0;
            Maximum = 1000;
            Height = 30;
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw | ControlStyles.UserPaint, true);
            marqueeTimer=new System.Windows.Forms.Timer{Interval=35};marqueeTimer.Tick+=(s,e)=>{int width=Math.Max(54,Width/4);marqueeOffset+=Math.Max(4,Width/36);if(marqueeOffset>Width)marqueeOffset=-width;Invalidate();};
        }
        protected override void OnPaint(PaintEventArgs e)
        {
            base.OnPaint(e);
            e.Graphics.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
            Rectangle track = new Rectangle(0, 1, Math.Max(0, Width - 1), Math.Max(0, Height - 2));
            if (track.Width <= 0 || track.Height <= 0) return;
            using (var trackPath = CreateRoundedRectangle(track, 8))
            using (var trackBrush = new SolidBrush(Color.FromArgb(13, 19, 28)))
                e.Graphics.FillPath(trackBrush, trackPath);
            int fillWidth = indeterminate?Math.Max(54,track.Width/4):(int)Math.Round(track.Width * (double)(value - Minimum) / Math.Max(1, Maximum - Minimum));
            if (fillWidth > 0)
            {
                Rectangle fill = indeterminate?new Rectangle(track.X+marqueeOffset,track.Y,fillWidth,track.Height):new Rectangle(track.X, track.Y, Math.Min(track.Width, fillWidth), track.Height);
                using (var fillPath = CreateRoundedRectangle(fill, 8))
                using (var fillBrush = new System.Drawing.Drawing2D.LinearGradientBrush(fill, Color.FromArgb(48, 126, 235), Color.FromArgb(90, 165, 255), 0f))
                {if(indeterminate){using(var trackPath=CreateRoundedRectangle(track,8)){e.Graphics.SetClip(trackPath);e.Graphics.FillPath(fillBrush,fillPath);e.Graphics.ResetClip();}}else e.Graphics.FillPath(fillBrush, fillPath);}
            }
            string percent = indeterminate?"正在处理…":((int)Math.Round((value - Minimum) * 100.0 / Math.Max(1, Maximum - Minimum))).ToString() + "%";
            using (var font = new Font(Font.FontFamily, 10F, FontStyle.Bold))
                TextRenderer.DrawText(e.Graphics, percent, font, track, Color.White, TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.NoPrefix);
        }
        protected override void Dispose(bool disposing){if(disposing&&marqueeTimer!=null)marqueeTimer.Dispose();base.Dispose(disposing);}
        static System.Drawing.Drawing2D.GraphicsPath CreateRoundedRectangle(Rectangle bounds, int radius)
        {
            int d = radius * 2;
            var path = new System.Drawing.Drawing2D.GraphicsPath();
            path.AddArc(bounds.Left, bounds.Top, d, d, 180, 90);
            path.AddArc(bounds.Right - d, bounds.Top, d, d, 270, 90);
            path.AddArc(bounds.Right - d, bounds.Bottom - d, d, d, 0, 90);
            path.AddArc(bounds.Left, bounds.Bottom - d, d, d, 90, 90);
            path.CloseFigure();
            return path;
        }
    }
    sealed class ScanProgress { public int Scanned, Total; }
    sealed class CleanupReport
    {
        public List<Candidate> Remaining = new List<Candidate>();
        public ResidueReport RemainingSummary;
        public List<string> DeletedItems = new List<string>();
        public List<string> FailedItems = new List<string>();
        public int Removed;
        public string Errors = "";
    }
    static class Program
    {
        [STAThread] static void Main()
        {
            bool createdNew;
            using (var instanceMutex = new Mutex(true, @"Local\koka.WindowsSoftwareManager", out createdNew))
            {
                if (!createdNew) return;
                // Older builds did not use the mutex. Wait for a simultaneous launch to exit,
                // then refuse to start beside any older koka.exe that is still running.
                using (Process current = Process.GetCurrentProcess())
                {
                    string[] processNames = new[] { current.ProcessName, "koka", "koka-new" }.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
                    for (int attempt = 0; attempt < 10; attempt++)
                    {
                        bool anotherInstance = false;
                        foreach (string processName in processNames)
                        {
                            foreach (Process candidate in Process.GetProcessesByName(processName))
                            {
                                using (candidate)
                                {
                                    try
                                    {
                                        if (candidate.Id != current.Id && candidate.SessionId == current.SessionId)
                                        {
                                            anotherInstance = true;
                                            break;
                                        }
                                    }
                                    catch { }
                                }
                            }
                            if (anotherInstance) break;
                        }
                        if (!anotherInstance) break;
                        if (attempt == 9) return;
                        Thread.Sleep(100);
                    }
                }
                try
                {
                    Application.EnableVisualStyles();
                    Application.SetCompatibleTextRenderingDefault(false);
                    Application.Run(new MainForm());
                }
                finally { try { instanceMutex.ReleaseMutex(); } catch { } }
            }
        }
    }
    sealed class ShiftScrollListView : ListView
    {
        const int WM_MOUSEWHEEL = 0x020A;
        const int LVM_SCROLL = 0x1014;
        const int LVM_SETEXTENDEDLISTVIEWSTYLE = 0x1036;
        const int LVS_EX_DOUBLEBUFFER = 0x00010000;
        [DllImport("user32.dll", CharSet=CharSet.Auto)] static extern IntPtr SendMessage(IntPtr hWnd,int msg,IntPtr wParam,IntPtr lParam);
        public ShiftScrollListView(){DoubleBuffered=true;SetStyle(ControlStyles.OptimizedDoubleBuffer|ControlStyles.AllPaintingInWmPaint,true);}
        protected override void OnHandleCreated(EventArgs e){base.OnHandleCreated(e);SendMessage(Handle,LVM_SETEXTENDEDLISTVIEWSTYLE,new IntPtr(LVS_EX_DOUBLEBUFFER),new IntPtr(LVS_EX_DOUBLEBUFFER));}
        protected override void WndProc(ref Message m)
        {
            if(m.Msg==WM_MOUSEWHEEL&&(ModifierKeys&Keys.Shift)==Keys.Shift)
            {
                int delta=(short)(((long)m.WParam>>16)&0xffff);int pixels=Math.Max(60,Math.Abs(delta));
                SendMessage(Handle,LVM_SCROLL,new IntPtr(delta>0?-pixels:pixels),IntPtr.Zero);return;
            }
            base.WndProc(ref m);
        }
    }
    sealed class KokaColorTable : ProfessionalColorTable
    {
        readonly bool dark;
        public KokaColorTable(bool isDark){dark=isDark;}
        public override Color ToolStripDropDownBackground { get { return dark?Color.FromArgb(28,35,46):Color.White; } }
        public override Color MenuItemSelected { get { return dark?Color.FromArgb(43,68,104):Color.FromArgb(220,235,255); } }
        public override Color MenuItemBorder { get { return dark?Color.FromArgb(70,94,126):Color.FromArgb(170,200,240); } }
        public override Color ImageMarginGradientBegin { get { return dark?Color.FromArgb(28,35,46):Color.White; } }
        public override Color ImageMarginGradientMiddle { get { return dark?Color.FromArgb(28,35,46):Color.White; } }
        public override Color ImageMarginGradientEnd { get { return dark?Color.FromArgb(28,35,46):Color.White; } }
        public override Color ToolStripBorder { get { return dark?Color.FromArgb(52,64,81):Color.FromArgb(220,227,237); } }
    }
    static class NativeTheme
    {
        [DllImport("uxtheme.dll", CharSet=CharSet.Unicode)] static extern int SetWindowTheme(IntPtr hwnd,string appName,string idList);
        [DllImport("dwmapi.dll")] static extern int DwmSetWindowAttribute(IntPtr hwnd,int attribute,ref int value,int size);
        public static void SetControl(Control control,bool dark)
        {
            try{if(control!=null&&control.IsHandleCreated)SetWindowTheme(control.Handle,dark?"DarkMode_Explorer":null,null);}catch{}
        }
        public static void SetForm(Form form,bool dark,Color surface,Color text,Color border)
        {
            if(form==null||!form.IsHandleCreated)return;
            try{int enabled=dark?1:0;int hr=DwmSetWindowAttribute(form.Handle,20,ref enabled,4);if(hr<0)DwmSetWindowAttribute(form.Handle,19,ref enabled,4);int caption=ColorRef(surface),captionText=ColorRef(text),frame=ColorRef(border);DwmSetWindowAttribute(form.Handle,35,ref caption,4);DwmSetWindowAttribute(form.Handle,36,ref captionText,4);DwmSetWindowAttribute(form.Handle,34,ref frame,4);}catch{}
        }
        static int ColorRef(Color color){return color.R|(color.G<<8)|(color.B<<16);}
    }
    sealed class MainForm : Form
    {
        readonly List<AppInfo> inventory = new List<AppInfo>();
        readonly List<AppInfo> archivedDataApps = new List<AppInfo>();
        readonly ListView software = new ShiftScrollListView();
        readonly ListView dataTree = new ShiftScrollListView();
        readonly ListView systemFiles = new ShiftScrollListView();
        ColumnHeader softwareFiller, dataFiller, systemFiller;
        readonly List<SystemEntry> systemInventory = new List<SystemEntry>();
        readonly HashSet<string> expandedDataApps = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        readonly Dictionary<string,int> expandedDataRowsVisible = new Dictionary<string,int>(StringComparer.OrdinalIgnoreCase);
        System.Windows.Forms.Timer dataExpandTimer;
        string dataExpandKey;
        int dataExpandTarget;
        System.Windows.Forms.Timer pageSwitchTimer;
        Control pageSwitchControl;
        Rectangle pageSwitchTarget;
        readonly TextBox filter = new TextBox();
        readonly Panel sortBox = new Panel();
        readonly Panel stateFilterBox = new Panel();
        readonly Label stateFilterLabel = new Label();
        readonly ContextMenuStrip stateFilterMenu = new ContextMenuStrip();
        int allFilterMode;
        readonly Label sortLabel = new Label();
        readonly ContextMenuStrip sortMenu = new ContextMenuStrip();
        readonly Label countLabel = new Label();
        readonly ImageList appIcons = new ImageList();
        readonly HashSet<string> iconLoads = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        readonly ContextMenuStrip appMenu = new ContextMenuStrip();
        readonly ContextMenuStrip dataMenu = new ContextMenuStrip();
        readonly ToolStripMenuItem deleteDataMenu = new ToolStripMenuItem("删除此文件或注册表项");
        readonly Panel pinnedDataHeader = new Panel();
        readonly PictureBox pinnedDataIcon = new PictureBox();
        readonly Label pinnedDataLabel = new Label();
        string pinnedDataAppKey;
        readonly ToolStripMenuItem uninstallMenu = new ToolStripMenuItem("卸载软件");
        readonly ToolStripMenuItem openLocationMenu = new ToolStripMenuItem("打开当前软件安装位置");
        readonly ToolStripMenuItem detailsMenu = new ToolStripMenuItem("查看详细信息");
        readonly ToolStripMenuItem cleanResiduesMenu = new ToolStripMenuItem("清理残留");
        readonly ToolStripMenuItem viewResiduesMenu = new ToolStripMenuItem("查看残留文件");
        readonly ToolStripMenuItem forceRemoveMenu = new ToolStripMenuItem("全盘扫描候选（仅查看）");
        readonly Button allTab = new Button();
        readonly Button installedTab = new Button();
        readonly Button uninstalledTab = new Button();
        readonly Button systemTab = new Button();
        readonly Button scanDataButton = new Button();
        readonly Button deleteHistoryButton = new Button();
        readonly ToolTip tips = new ToolTip();
        readonly Panel listHost = new Panel();
        readonly Label brandName = new Label();
        Form loadingForm;
        Label loadingLabel;
        KokaProgressBar loadingBar;
        readonly HashSet<string> explicitlyUninstalled = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        readonly object classificationLock = new object();
        bool systemScanRunning;
        bool installedDataScanRunning;
        bool installedDataScanComplete;
        int activeTab;
        bool sizeCalcRunning;
        bool appsLoading;
        int sortMode;
        AppInfo current;
        bool darkTheme=true;
        bool filterIsPlaceholder=true;
        bool hasSavedBounds;
        Rectangle savedBounds;
        string settingsPath;
        readonly Dictionary<string,int> savedColumnWidths=new Dictionary<string,int>(StringComparer.OrdinalIgnoreCase);
        Color pageColor, surfaceColor, alternateColor, textColor, mutedColor, borderColor, accentColor, selectedColor;
        CancellationTokenSource dataScanCancellation;
        CancellationTokenSource appLoadCancellation;
        bool closingLoadingProgrammatically;
        bool startupLoading=true;
        bool finalCacheWriteRunning;
        string dataCachePath;
        string dataCacheDeltaPath;
        readonly Dictionary<string,string> pendingCacheBaseline=new Dictionary<string,string>(StringComparer.OrdinalIgnoreCase);
        bool pendingCacheFullRewrite=true;
        string deleteHistoryPath;
        readonly object deleteHistoryLock = new object();
        string cachedInventorySignature;
        bool dataCacheDirty=true;
        bool fullDataScanRequired=true;
        int dataChangeGeneration;
        readonly HashSet<string> changedDataAppKeys=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        bool dataCacheLoaded;
        bool dataCacheValidationComplete;
        bool dataCacheValidationRunning;
        bool dataCacheLoading;
        bool dataMonitoringStarted;
        bool dataMonitoringStopped;
        bool dataInventoryReloadPending;
        string lastRegistrySignature;
        readonly List<FileSystemWatcher> dataWatchers=new List<FileSystemWatcher>();
        System.Windows.Forms.Timer dataRescanTimer;
        System.Threading.Timer registryPollTimer;
        int registryPollRunning;
        void ShowLoading(string text)
        {
            if(loadingForm!=null&&!loadingForm.IsDisposed){loadingLabel.Text=text;loadingForm.BringToFront();return;}
            loadingLabel=new Label{Text=text,Dock=DockStyle.Top,Height=68,TextAlign=ContentAlignment.MiddleCenter,Padding=new Padding(18,8,18,8),Font=new Font("Microsoft YaHei UI",10F,FontStyle.Bold),BackColor=pageColor};
            loadingBar=new KokaProgressBar{Dock=DockStyle.Top,Height=32,Minimum=0,Maximum=1000,Value=0,BackColor=pageColor};
            loadingForm=new Form{Text="koka - 请稍候",Width=560,Height=170,Padding=new Padding(14),BackColor=pageColor,FormBorderStyle=FormBorderStyle.FixedDialog,MaximizeBox=false,MinimizeBox=false,ControlBox=true,StartPosition=FormStartPosition.Manual,ShowInTaskbar=false,Icon=this.Icon};loadingForm.FormClosing+=delegate(object sender,FormClosingEventArgs e){if(closingLoadingProgrammatically)return;bool wasStartupLoading=startupLoading;CancellationTokenSource scan=dataScanCancellation,appLoad=appLoadCancellation;if(scan!=null&&!scan.IsCancellationRequested)scan.Cancel();if(appLoad!=null&&!appLoad.IsCancellationRequested)appLoad.Cancel();e.Cancel=false;Move-=CenterLoadingForm;Resize-=CenterLoadingForm;if(ReferenceEquals(loadingForm,sender)){loadingForm=null;loadingLabel=null;loadingBar=null;}if(wasStartupLoading){startupLoading=false;BeginInvoke((Action)delegate{if(!IsDisposed&&!Disposing)Close();});return;}Enabled=true;Activate();};loadingForm.Controls.Add(loadingBar);loadingForm.Controls.Add(loadingLabel);ApplyThemeToControls(loadingForm);loadingForm.Shown+=delegate{NativeTheme.SetForm(loadingForm,darkTheme,surfaceColor,textColor,borderColor);};loadingForm.Location=GetLoadingLocation();loadingForm.Show(this);loadingForm.BringToFront();Enabled=false;
            if(startupLoading&&loadingForm!=null)loadingForm.Owner=null;
            Move+=CenterLoadingForm;Resize+=CenterLoadingForm;
        }
        void ReplaceLoading(string text)
        {
            if(InvokeRequired){try{BeginInvoke((Action)delegate{ReplaceLoading(text);});}catch{}return;}
            Move-=CenterLoadingForm;Resize-=CenterLoadingForm;if(loadingForm!=null){closingLoadingProgrammatically=true;try{loadingForm.Close();loadingForm.Dispose();}catch{}finally{closingLoadingProgrammatically=false;}loadingForm=null;loadingLabel=null;loadingBar=null;}
            ShowLoading(text);
        }
        Point GetLoadingLocation(){return PointToScreen(new Point(Math.Max(0,(ClientSize.Width-560)/2),Math.Max(0,(ClientSize.Height-170)/2)));}
        void CenterLoadingForm(object sender,EventArgs e){if(loadingForm!=null&&!loadingForm.IsDisposed)loadingForm.Location=GetLoadingLocation();}
        void UpdateLoadingProgress(int value,string text){try{if(IsDisposed||loadingForm==null||loadingForm.IsDisposed)return;if(InvokeRequired){BeginInvoke((Action)delegate{UpdateLoadingProgress(value,text);});return;}int v=Math.Max(0,Math.Min(1000,value));loadingBar.IsIndeterminate=false;loadingBar.Value=v;loadingLabel.Text=text;}catch{}}
        void HideLoading(){if(InvokeRequired){try{BeginInvoke((Action)HideLoading);}catch{}return;}Move-=CenterLoadingForm;Resize-=CenterLoadingForm;if(loadingForm!=null){closingLoadingProgrammatically=true;try{loadingForm.Close();loadingForm.Dispose();}catch{}finally{closingLoadingProgrammatically=false;}loadingForm=null;loadingLabel=null;loadingBar=null;}if(!IsDisposed&&!Disposing){Enabled=true;if(startupLoading){startupLoading=false;Show();}Activate();}}
        void SetProgress(ProgressBar bar,Label label,int value,string text){try{if(bar==null||bar.IsDisposed||label==null||label.IsDisposed)return;if(InvokeRequired){BeginInvoke((Action)delegate{SetProgress(bar,label,value,text);});return;}int v=Math.Max(0,Math.Min(1000,value));bar.Value=v;label.Text=text+" "+(v/10)+"%";}catch{}}
        string AppKey(AppInfo app){return Norm(app.Name)+"|"+Norm(app.Version)+"|"+Norm(app.Publisher);}
        bool WasExplicitlyUninstalled(AppInfo app){lock(classificationLock)return explicitlyUninstalled.Contains(AppKey(app));}
        void MarkExplicitlyUninstalled(AppInfo app){lock(classificationLock)explicitlyUninstalled.Add(AppKey(app));}
        public MainForm()
        {
            LoadUserSettings();
            dataCachePath=Path.Combine(Path.GetDirectoryName(Application.ExecutablePath),"koka-data","scan-cache.tsv");dataCacheDeltaPath=dataCachePath+".delta";deleteHistoryPath=Path.Combine(Path.GetDirectoryName(Application.ExecutablePath),"koka-data","delete-history.tsv");
            Text = "koka - Windows 软件管理"; Size = new Size(1120, 760); MinimumSize = new Size(860, 600); StartPosition = FormStartPosition.CenterScreen; Font = new Font("Microsoft YaHei UI", 9F);try{Icon=Icon.ExtractAssociatedIcon(Application.ExecutablePath);}catch{}
            if(hasSavedBounds&&savedBounds.Width>=MinimumSize.Width&&savedBounds.Height>=MinimumSize.Height&&Screen.AllScreens.Any(s=>s.WorkingArea.IntersectsWith(savedBounds))){StartPosition=FormStartPosition.Manual;Bounds=savedBounds;}
            var layout = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(18,14,18,14), RowCount = 5, ColumnCount = 1 };
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 68)); layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 48)); layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 52)); layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100)); layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 48)); Controls.Add(layout);
            var header=new Panel{Dock=DockStyle.Fill,Margin=new Padding(0,0,0,8)};
            header.Paint+=(s,e)=>{e.Graphics.SmoothingMode=System.Drawing.Drawing2D.SmoothingMode.AntiAlias;Rectangle r=new Rectangle(1,1,header.Width-3,header.Height-3);using(var p=RoundedRectangle(r,10))using(var b=new System.Drawing.Drawing2D.LinearGradientBrush(r,Color.FromArgb(31,45,64),Color.FromArgb(23,32,44),90f))e.Graphics.FillPath(b,p);using(var p=RoundedRectangle(r,10))using(var pen=new Pen(Color.FromArgb(48,66,88)))e.Graphics.DrawPath(pen,p);using(var b=new SolidBrush(accentColor))e.Graphics.FillRectangle(b,1,12,3,header.Height-24);using(var pen=new Pen(Color.FromArgb(24,120,164,230),1.2f)){int x=header.Width-112;e.Graphics.DrawArc(pen,x,7,96,50,205,130);e.Graphics.DrawArc(pen,x+18,16,65,34,205,130);}using(var b=new SolidBrush(Color.FromArgb(70,120,164,230)))e.Graphics.FillEllipse(b,header.Width-50,18,7,7);};
            var logo=new PictureBox{Size=new Size(46,46),Location=new Point(14,7),SizeMode=PictureBoxSizeMode.Zoom};try{using(Icon appIcon=Icon.ExtractAssociatedIcon(Application.ExecutablePath))logo.Image=appIcon.ToBitmap();}catch{}
            brandName.Text="koka";brandName.Font=new Font("Microsoft YaHei UI",21F,FontStyle.Bold);brandName.AutoSize=true;brandName.Location=new Point(76,15);
            header.Controls.Add(logo);header.Controls.Add(brandName);layout.Controls.Add(header,0,0);
            var tabs = new FlowLayoutPanel { Dock = DockStyle.Fill, WrapContents = false, Padding=new Padding(0,2,0,0),Margin=new Padding(0,0,0,6) };
            ConfigureTab(allTab, "全部", 0); ConfigureTab(installedTab, "已安装", 1); ConfigureTab(uninstalledTab, "数据", 2); ConfigureTab(systemTab, "系统文件", 3);
            allTab.Click += delegate { SetTab(0); }; installedTab.Click += delegate { SetTab(1); }; uninstalledTab.Click += delegate { SetTab(2); }; systemTab.Click += delegate { SetTab(3); };
            tabs.Controls.Add(allTab); tabs.Controls.Add(installedTab); tabs.Controls.Add(uninstalledTab); tabs.Controls.Add(systemTab); layout.Controls.Add(tabs, 0, 1);
            var top = new FlowLayoutPanel { Dock = DockStyle.Fill, WrapContents = false, Padding=new Padding(0,6,0,0),Margin=new Padding(0,0,0,8) };
            var searchBox=new Panel{Width=380,Height=36,Margin=new Padding(0,1,12,0)};searchBox.Paint+=(s,e)=>DrawSearchBox(e.Graphics,searchBox.ClientRectangle);
            filter.Width = 338; filter.Height=22;filter.Location=new Point(34,7);filter.BorderStyle=BorderStyle.None;filter.Text = "输入名称或发布者筛选"; filter.ForeColor = Color.Gray;filter.Margin=Padding.Empty;
            filter.Enter += delegate { if (filterIsPlaceholder) { filter.Text = ""; filterIsPlaceholder=false;filter.ForeColor = textColor; }searchBox.Invalidate(); };
            filter.Leave += delegate { if (String.IsNullOrWhiteSpace(filter.Text)) { filter.Text = "输入名称或发布者筛选";filterIsPlaceholder=true;filter.ForeColor = mutedColor; }searchBox.Invalidate(); };
            filter.TextChanged += delegate { if(activeTab==3)RenderSystemFiles();else ShowApps(); };searchBox.Controls.Add(filter);top.Controls.Add(searchBox);
            stateFilterBox.Width=136;stateFilterBox.Height=36;stateFilterBox.Margin=new Padding(0,1,8,0);stateFilterBox.Cursor=Cursors.Hand;stateFilterBox.Paint+=(s,e)=>DrawSortBox(e.Graphics,stateFilterBox.ClientRectangle);stateFilterLabel.Text="全部状态";stateFilterLabel.Dock=DockStyle.Fill;stateFilterLabel.TextAlign=ContentAlignment.MiddleLeft;stateFilterLabel.Padding=new Padding(12,0,30,0);stateFilterLabel.Cursor=Cursors.Hand;stateFilterBox.Controls.Add(stateFilterLabel);stateFilterBox.Click+=delegate{stateFilterMenu.Show(stateFilterBox,0,stateFilterBox.Height+2);};stateFilterLabel.Click+=delegate{stateFilterMenu.Show(stateFilterBox,0,stateFilterBox.Height+2);};string[] stateNames={"全部","已安装","残留"};for(int i=0;i<stateNames.Length;i++){int mode=i;var option=new ToolStripMenuItem(stateNames[i]){Tag=mode};option.Click+=(s,e)=>{allFilterMode=mode;stateFilterLabel.Text=stateNames[mode];ShowApps();};stateFilterMenu.Items.Add(option);}top.Controls.Add(stateFilterBox);
            sortBox.Width=204;sortBox.Height=36;sortBox.Margin=new Padding(0,1,10,0);sortBox.Cursor=Cursors.Hand;sortBox.Paint+=(s,e)=>DrawSortBox(e.Graphics,sortBox.ClientRectangle);sortLabel.Text="名称排序（A 到 Z）";sortLabel.Dock=DockStyle.Fill;sortLabel.TextAlign=ContentAlignment.MiddleLeft;sortLabel.Padding=new Padding(12,0,30,0);sortLabel.Cursor=Cursors.Hand;sortBox.Controls.Add(sortLabel);sortBox.Click+=ShowSortMenu;sortLabel.Click+=ShowSortMenu;string[] sortNames={"名称排序（A 到 Z）","大小排序（从高到低）","大小排序（从低到高）"};for(int i=0;i<sortNames.Length;i++){int mode=i;var option=new ToolStripMenuItem(sortNames[i]){Tag=mode};option.Click+=(s,e)=>{sortMode=mode;sortLabel.Text=sortNames[mode];ShowApps();};sortMenu.Items.Add(option);}top.Controls.Add(sortBox);
            scanDataButton.Text="扫描";scanDataButton.Width=72;scanDataButton.Height=34;scanDataButton.Margin=new Padding(0,1,8,0);scanDataButton.FlatStyle=FlatStyle.Flat;scanDataButton.FlatAppearance.BorderSize=1;scanDataButton.Cursor=Cursors.Hand;scanDataButton.Visible=false;scanDataButton.Click+=delegate{if(activeTab==2&&!installedDataScanRunning){dataCacheValidationComplete=true;fullDataScanRequired=true;dataCacheDirty=true;installedDataScanComplete=false;StartInstalledDataScan();}};top.Controls.Add(scanDataButton);deleteHistoryButton.Text="删除记录";deleteHistoryButton.Width=88;deleteHistoryButton.Height=34;deleteHistoryButton.Margin=new Padding(0,1,8,0);deleteHistoryButton.FlatStyle=FlatStyle.Flat;deleteHistoryButton.FlatAppearance.BorderSize=1;deleteHistoryButton.Click+=ShowDeleteHistory;top.Controls.Add(deleteHistoryButton);
            var reload = new Button { Width = 38, Height = 34, Margin = new Padding(0, 1, 0, 0), FlatStyle=FlatStyle.Flat,BackColor=Color.White,ForeColor=Color.FromArgb(45,125,235),Cursor=Cursors.Hand,Tag="refresh" };reload.FlatAppearance.BorderColor=Color.FromArgb(210,225,245);reload.FlatAppearance.BorderSize=1;reload.Paint+=(s,e)=>DrawRefreshIcon(e.Graphics,reload.ClientRectangle,reload.ForeColor);reload.Click += delegate { if(activeTab==3)LoadSystemFiles();else if(activeTab==2){if(!dataCacheLoading)LoadDataCacheForDataTab();}else LoadApps(); }; tips.SetToolTip(reload,"刷新列表"); top.Controls.Add(reload); layout.Controls.Add(top, 0, 2);
            appIcons.ImageSize = new Size(32, 32); appIcons.ColorDepth = ColorDepth.Depth32Bit;
            software.Dock = DockStyle.Fill; software.View = View.Details; software.FullRowSelect = true; software.HideSelection = false; software.MultiSelect = false; software.SmallImageList = appIcons;software.OwnerDraw=true;software.DrawColumnHeader+=DrawListHeader;software.DrawItem+=delegate{};software.DrawSubItem+=DrawListSubItem;software.GridLines=false;software.BorderStyle=BorderStyle.None;software.Font=new Font("Microsoft YaHei UI",9.5F);appIcons.ImageSize=new Size(34,34);
            software.Columns.Add("软件名称", 240);software.Columns.Add("类型",100); software.Columns.Add("大小", 100); software.Columns.Add("状态", 130); software.Columns.Add("版本", 120); software.Columns.Add("发布者", 170); software.Columns.Add("安装位置", 300);softwareFiller=software.Columns.Add(" ",0); software.SelectedIndexChanged += SelectApp; software.MouseUp += SoftwareMouseUp; appMenu.Opening += AppMenuOpening; listHost.Dock=DockStyle.Fill;listHost.Padding=new Padding(1);listHost.Margin=new Padding(0); listHost.Controls.Add(software); layout.Controls.Add(listHost, 0, 3);
            dataTree.Dock=DockStyle.Fill;dataTree.View=View.Details;dataTree.FullRowSelect=true;dataTree.HideSelection=false;dataTree.OwnerDraw=true;dataTree.DrawColumnHeader+=DrawListHeader;dataTree.DrawItem+=delegate{};dataTree.DrawSubItem+=DrawListSubItem;dataTree.GridLines=false;dataTree.BorderStyle=BorderStyle.None;dataTree.Font=new Font("Microsoft YaHei UI",9.5F);dataTree.SmallImageList=appIcons;dataTree.Columns.Add("数据项 / 软件",340);dataTree.Columns.Add("类型",130);dataTree.Columns.Add("文件或注册表位置",700);dataFiller=dataTree.Columns.Add(" ",0);dataTree.MouseClick+=DataTreeMouseClick;dataTree.MouseUp+=DataTreeMouseUp;dataMenu.Items.Add(deleteDataMenu);deleteDataMenu.Click+=DeleteSelectedDataItem;listHost.Controls.Add(dataTree);dataTree.Visible=false;pinnedDataHeader.Dock=DockStyle.Top;pinnedDataHeader.Height=42;pinnedDataHeader.Visible=false;pinnedDataHeader.Padding=new Padding(10,4,8,4);pinnedDataHeader.Paint+=(s,e)=>{using(var pen=new Pen(borderColor))e.Graphics.DrawLine(pen,0,pinnedDataHeader.Height-1,pinnedDataHeader.Width,pinnedDataHeader.Height-1);};pinnedDataIcon.Size=new Size(32,32);pinnedDataIcon.Location=new Point(7,5);pinnedDataIcon.SizeMode=PictureBoxSizeMode.Zoom;pinnedDataLabel.Location=new Point(48,0);pinnedDataLabel.Size=new Size(600,42);pinnedDataLabel.TextAlign=ContentAlignment.MiddleLeft;pinnedDataLabel.Font=new Font("Microsoft YaHei UI",9.5F,FontStyle.Bold);pinnedDataHeader.Controls.Add(pinnedDataIcon);pinnedDataHeader.Controls.Add(pinnedDataLabel);listHost.Controls.Add(pinnedDataHeader);pinnedDataHeader.BringToFront();
            systemFiles.Dock=DockStyle.Fill;systemFiles.View=View.Details;systemFiles.FullRowSelect=true;systemFiles.OwnerDraw=true;systemFiles.DrawColumnHeader+=DrawListHeader;systemFiles.DrawItem+=delegate{};systemFiles.DrawSubItem+=DrawListSubItem;systemFiles.GridLines=false;systemFiles.BorderStyle=BorderStyle.None;systemFiles.Columns.Add("文件名",300);systemFiles.Columns.Add("类型",160);systemFiles.Columns.Add("大小",110);systemFiles.Columns.Add("完整路径",700);systemFiller=systemFiles.Columns.Add(" ",0);listHost.Controls.Add(systemFiles);systemFiles.Visible=false;listHost.Resize+=delegate{FitFillerColumn(software,softwareFiller);FitFillerColumn(dataTree,dataFiller);FitFillerColumn(systemFiles,systemFiller);};ApplySavedColumnWidths("software",software,softwareFiller);ApplySavedColumnWidths("data",dataTree,dataFiller);ApplySavedColumnWidths("system",systemFiles,systemFiller);software.ColumnWidthChanged+=delegate{FitFillerColumn(software,softwareFiller);};dataTree.ColumnWidthChanged+=delegate{FitFillerColumn(dataTree,dataFiller);};systemFiles.ColumnWidthChanged+=delegate{FitFillerColumn(systemFiles,systemFiller);};
            appMenu.Items.Add(uninstallMenu); appMenu.Items.Add(openLocationMenu);appMenu.Items.Add(detailsMenu);appMenu.Items.Add(new ToolStripSeparator());appMenu.Items.Add(forceRemoveMenu);
            appMenu.Items.Add(new ToolStripSeparator()); appMenu.Items.Add(viewResiduesMenu); appMenu.Items.Add(cleanResiduesMenu);
            uninstallMenu.Click += Uninstall;
            openLocationMenu.Click += OpenInstallLocation;
            detailsMenu.Click += ShowAppDetails;
            cleanResiduesMenu.Click += CleanCurrentResidues;
            viewResiduesMenu.Click += ShowResidueDetails;
            forceRemoveMenu.Click += ShowGlobalScanPreview;
            countLabel.Dock = DockStyle.Fill; countLabel.TextAlign = ContentAlignment.MiddleLeft;countLabel.Padding=new Padding(14,0,8,0);countLabel.Margin=new Padding(0,10,0,0);countLabel.Font=new Font("Microsoft YaHei UI",9F,FontStyle.Bold);countLabel.Paint+=(s,e)=>{using(var pen=new Pen(borderColor))e.Graphics.DrawLine(pen,0,0,countLabel.Width,0);}; layout.Controls.Add(countLabel, 0, 4);
            ApplyTheme();FormClosing+=delegate{if(dataScanCancellation!=null)dataScanCancellation.Cancel();StopDataMonitoring();SaveUserSettings();};
            Shown += delegate { NativeTheme.SetForm(this,darkTheme,surfaceColor,textColor,borderColor);Hide();LoadApps(); };
            HandleCreated+=delegate{NativeTheme.SetForm(this,darkTheme,surfaceColor,textColor,borderColor);};
        }
        void LoadApps()
        {
            if(installedDataScanRunning){dataInventoryReloadPending=true;return;}
            if(appsLoading)return;
            appsLoading=true;bool restoreDataCache=dataCacheLoaded;
            software.Enabled=false;
            ShowLoading("正在读取软件清单…");
            var cancellation=new CancellationTokenSource();appLoadCancellation=cancellation;
            Task.Run(()=>
            {
                var loadedInventory=new List<AppInfo>();
                var roots=new[]{
                    new KeyValuePair<RegistryHive,RegistryView>(RegistryHive.LocalMachine,RegistryView.Registry64),
                    new KeyValuePair<RegistryHive,RegistryView>(RegistryHive.LocalMachine,RegistryView.Registry32),
                    new KeyValuePair<RegistryHive,RegistryView>(RegistryHive.CurrentUser,RegistryView.Registry64),
                    new KeyValuePair<RegistryHive,RegistryView>(RegistryHive.CurrentUser,RegistryView.Registry32)
                };
                for(int i=0;i<roots.Length;i++)
                {
                    cancellation.Token.ThrowIfCancellationRequested();ReadApps(roots[i].Key,roots[i].Value,loadedInventory,cancellation.Token);
                    UpdateLoadingProgress((i+1)*250,"正在读取软件清单…");
                }
                foreach(AppInfo app in loadedInventory)app.IsInstalled=true;
                UpdateLoadingProgress(1000,"软件清单读取完成");
                return loadedInventory;
            },cancellation.Token).ContinueWith(task=>
            {
                try{BeginInvoke((Action)delegate
                {
                    appsLoading=false;
                    if(appLoadCancellation==cancellation)appLoadCancellation=null;cancellation.Dispose();
                    software.Enabled=true;
                    if(task.IsCanceled){HideLoading();countLabel.Text="启动扫描已取消，已返回程序。可以稍后刷新软件清单。";return;}
                    if(task.Status!=TaskStatus.RanToCompletion)
                    {
                        HideLoading();
                        countLabel.Text="读取软件列表失败，请点击刷新重试。";
                        return;
                    }
                    inventory.Clear();inventory.AddRange(task.Result);if(restoreDataCache)dataCacheLoaded=false;
                    inventory.Sort((a,b)=>String.Compare(a.Name,b.Name,StringComparison.CurrentCultureIgnoreCase));
                    appIcons.Images.Clear();
                    lastRegistrySignature=BuildInventorySignature();

                    StartDataMonitoringAsync();
                    ShowApps();
                    if(!dataCacheLoaded){UpdateLoadingProgress(0,"软件清单已读取，正在载入本地缓存…");if(loadingBar!=null)loadingBar.IsIndeterminate=true;LoadDataCacheForDataTab();}else HideLoading();
                });}
                catch{appsLoading=false;software.Enabled=true;HideLoading();}
            });
        }        void LoadDataCacheForDataTab()
        {
            if(dataCacheLoading||appsLoading)return;dataCacheLoading=true;int generation=dataChangeGeneration;dataTree.Enabled=false;
            if(startupLoading&&loadingForm!=null){loadingLabel.Text="正在载入本地缓存…";loadingBar.Value=0;loadingBar.IsIndeterminate=true;}
            Task.Run(()=>ApplyDataCache()).ContinueWith(task=>{try{BeginInvoke((Action)delegate{dataCacheLoading=false;if(task.Status!=TaskStatus.RanToCompletion){dataCacheLoaded=true;dataCacheDirty=true;fullDataScanRequired=true;}if(generation!=dataChangeGeneration)dataCacheDirty=true;lastRegistrySignature=BuildInventorySignature();dataTree.Enabled=true;if(activeTab!=2)ShowApps();if(dataInventoryReloadPending&&!appsLoading){dataInventoryReloadPending=false;LoadApps();return;}ShowApps();bool silentStartupValidation=startupLoading&&!fullDataScanRequired;if(silentStartupValidation)HideLoading();countLabel.Text="已加载本地缓存，正在后台检查变化…";BeginInvoke((Action)delegate{if(!installedDataScanRunning&&!appsLoading)ValidateDataCache(silentStartupValidation);});});}catch{dataCacheLoading=false;}});
        }        string CacheEncode(string value){return Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(value??""));}
        string CacheDecode(string value){return System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(value??""));}
        string CacheAppSignature(AppInfo app){return String.Join("\n",new[]{app.Name??"",app.Version??"",app.Publisher??"",app.Location??"",app.IsInstalled.ToString()}.Concat(app.DataItems.Select(x=>String.Join("\t",new[]{x.Kind??"",x.Path??"",x.Size.ToString(),x.Fingerprint??"",x.RemovalCandidate==null?"":x.RemovalCandidate.Registry.ToString(),x.RemovalCandidate==null?"":x.RemovalCandidate.IsFile.ToString(),x.RemovalCandidate==null?"":x.RemovalCandidate.Key??""})).OrderBy(x=>x,StringComparer.OrdinalIgnoreCase)));}
        string BuildInventorySignature(){return String.Join("\n",inventory.Where(a=>a.IsInstalled).Select(AppKey).Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(x=>x,StringComparer.OrdinalIgnoreCase).ToArray());}
        string ReadRegistrySignature()
        {
            var keys=new HashSet<string>(StringComparer.OrdinalIgnoreCase);string rootPath=@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
            foreach(RegistryHive hive in new[]{RegistryHive.LocalMachine,RegistryHive.CurrentUser})foreach(RegistryView view in new[]{RegistryView.Registry64,RegistryView.Registry32})try{using(var root=RegistryKey.OpenBaseKey(hive,view).OpenSubKey(rootPath)){if(root==null)continue;foreach(string name in root.GetSubKeyNames())try{using(var key=root.OpenSubKey(name)){if(key==null)continue;string display=Convert.ToString(key.GetValue("DisplayName")),command=Convert.ToString(key.GetValue("UninstallString"));int system;Int32.TryParse(Convert.ToString(key.GetValue("SystemComponent",0)),out system);if(String.IsNullOrWhiteSpace(display)||String.IsNullOrWhiteSpace(command)||system==1||!String.IsNullOrEmpty(Convert.ToString(key.GetValue("ParentKeyName"))))continue;keys.Add(Norm(display)+"|"+Norm(Convert.ToString(key.GetValue("DisplayVersion")))+"|"+Norm(Convert.ToString(key.GetValue("Publisher"))));}}catch{}}}catch{}
            return String.Join("\n",keys.OrderBy(x=>x,StringComparer.OrdinalIgnoreCase).ToArray());
        }
        string GetDataItemFingerprint(DataItem item)
        {
            if(item==null)return "";Candidate c=item.RemovalCandidate;
            if(c!=null&&c.Registry){try{using(var key=RegistryKey.OpenBaseKey(c.Hive,c.View).OpenSubKey(c.Key)){if(key==null)return "missing";var values=key.GetValueNames().OrderBy(x=>x,StringComparer.OrdinalIgnoreCase).Select(x=>{object value=key.GetValue(x);string text=value is byte[]?Convert.ToBase64String((byte[])value):value is string[]?String.Join("\u001f",(string[])value):Convert.ToString(value);return x+":"+key.GetValueKind(x)+"="+text;});string raw=String.Join("|",values.ToArray());using(var sha=SHA256.Create())return "R|"+BitConverter.ToString(sha.ComputeHash(System.Text.Encoding.UTF8.GetBytes(raw)));}}catch{return "error";}}
            string path=item.Path??"";try{if(File.Exists(path)){var info=new FileInfo(path);return "F|"+info.Length+"|"+info.LastWriteTimeUtc.Ticks;}if(Directory.Exists(path))return "D|"+Directory.GetLastWriteTimeUtc(path).Ticks;return "missing";}catch{return "error";}
        }
        void ApplyDataCache()
        {
            dataCacheLoaded=true;dataCacheValidationComplete=false;dataCacheDirty=true;fullDataScanRequired=true;installedDataScanComplete=false;changedDataAppKeys.Clear();cachedInventorySignature=null;if(!File.Exists(dataCachePath)&&!File.Exists(dataCacheDeltaPath))return;
            var cachedApps=new Dictionary<string,AppInfo>(StringComparer.OrdinalIgnoreCase);var previousInstalled=new Dictionary<string,bool>(StringComparer.OrdinalIgnoreCase);string storedSignature=null;bool interruptedScan=false;
            // Build this index once. Looking through the full inventory for every cached app
            // made startup time grow with cache rows multiplied by installed app count.
            var inventoryByKey=new Dictionary<string,AppInfo>(StringComparer.OrdinalIgnoreCase);
            foreach(AppInfo existing in inventory)if(!inventoryByKey.ContainsKey(AppKey(existing)))inventoryByKey.Add(AppKey(existing),existing);
            try{foreach(string cacheFile in new[]{dataCachePath,dataCacheDeltaPath}){if(!File.Exists(cacheFile))continue;foreach(string line in File.ReadLines(cacheFile,System.Text.Encoding.UTF8)){string[] p=line.TrimStart('\uFEFF').Split('\t');if(p.Length==0)continue;if(p[0]=="R"&&p.Length>1){interruptedScan=String.Equals(p[1],"INCOMPLETE",StringComparison.OrdinalIgnoreCase);continue;}if(p[0]=="S"&&p.Length>1){storedSignature=CacheDecode(p[1]);continue;}if((p[0]=="P"||p[0]=="X")&&p.Length>1){string key=CacheDecode(p[1]);AppInfo prior;if(cachedApps.TryGetValue(key,out prior)){prior.DataItems.Clear();prior.Residues.Clear();}if(p[0]=="X"){cachedApps.Remove(key);previousInstalled.Remove(key);AppInfo stale;if(inventoryByKey.TryGetValue(key,out stale)&&!stale.IsInstalled)inventory.Remove(stale);inventoryByKey.Remove(key);}continue;}if(p[0]=="A"&&p.Length>=6){string key=CacheDecode(p[1]);AppInfo app;if(!inventoryByKey.TryGetValue(key,out app)){app=new AppInfo{Name=CacheDecode(p[2]),Version=CacheDecode(p[3]),Publisher=CacheDecode(p[4]),Location=CacheDecode(p[5]),IsInstalled=false};inventory.Add(app);inventoryByKey.Add(key,app);}app.Name=CacheDecode(p[2]);app.Version=CacheDecode(p[3]);app.Publisher=CacheDecode(p[4]);app.Location=CacheDecode(p[5]);app.IsInstalled=p.Length>6&&Boolean.Parse(p[6]);cachedApps[key]=app;previousInstalled[key]=app.IsInstalled;continue;}if(p[0]=="D"&&p.Length>=11){string key=CacheDecode(p[1]);AppInfo app;if(!cachedApps.TryGetValue(key,out app))continue;Candidate c=new Candidate{Path=CacheDecode(p[3]),Registry=Boolean.Parse(p[5]),IsFile=Boolean.Parse(p[6]),Hive=(RegistryHive)Int32.Parse(p[7]),View=(RegistryView)Int32.Parse(p[8]),Key=CacheDecode(p[9])};var item=new DataItem{Kind=CacheDecode(p[2]),Path=c.Path,Size=Int64.Parse(p[4]),RemovalCandidate=c,Fingerprint=CacheDecode(p[10])};app.DataItems.Add(item);app.Residues.Add(c);}}}}catch{dataCacheDirty=true;fullDataScanRequired=true;return;}
            fullDataScanRequired=interruptedScan;dataCacheDirty=interruptedScan;cachedInventorySignature=storedSignature;
            foreach(AppInfo app in cachedApps.Values){if(app.DataItems.Count>0){app.SizeBytes=app.DataItems.Sum(x=>Math.Max(0,x.Size));app.HasKnownSize=true;app.SizeCalculationComplete=true;}else if(!app.IsInstalled){app.SizeBytes=0;app.HasKnownSize=true;app.SizeCalculationComplete=true;}string key=AppKey(app);bool wasInstalled;if(previousInstalled.TryGetValue(key,out wasInstalled)&&wasInstalled!=app.IsInstalled){changedDataAppKeys.Add(key);dataCacheDirty=true;}}
            foreach(AppInfo app in inventory.Where(a=>a.IsInstalled))if(!cachedApps.ContainsKey(AppKey(app))){changedDataAppKeys.Add(AppKey(app));dataCacheDirty=true;}
            string currentSignature=BuildInventorySignature();if(String.IsNullOrEmpty(storedSignature)){dataCacheDirty=true;fullDataScanRequired=true;}else if(!String.Equals(storedSignature,currentSignature,StringComparison.OrdinalIgnoreCase)&&changedDataAppKeys.Count==0){
                // No individual app was added, removed, or reclassified, so this is a stale
                // inventory signature rather than a reason to walk every file location again.
                dataCacheDirty=true;cachedInventorySignature=currentSignature;
            }
            installedDataScanComplete=!dataCacheDirty;lastRegistrySignature=currentSignature;
        }        void WriteCachedApp(StreamWriter writer,AppInfo app)
        {
            string key=AppKey(app);writer.WriteLine("A\t"+CacheEncode(key)+"\t"+CacheEncode(app.Name)+"\t"+CacheEncode(app.Version)+"\t"+CacheEncode(app.Publisher)+"\t"+CacheEncode(app.Location)+"\t"+app.IsInstalled);
            foreach(DataItem item in app.DataItems){Candidate c=item.RemovalCandidate??CandidateFromData(item.Kind,item.Path);item.RemovalCandidate=c;if(String.IsNullOrEmpty(item.Fingerprint))item.Fingerprint=GetDataItemFingerprint(item);writer.WriteLine("D\t"+CacheEncode(key)+"\t"+CacheEncode(item.Kind)+"\t"+CacheEncode(item.Path)+"\t"+item.Size+"\t"+c.Registry+"\t"+c.IsFile+"\t"+(int)c.Hive+"\t"+(int)c.View+"\t"+CacheEncode(c.Key)+"\t"+CacheEncode(item.Fingerprint));}
        }
        bool SaveDataCache(Action<int,string> progress=null)
        {
            if(String.IsNullOrEmpty(dataCachePath)||(!dataCacheLoaded&&!installedDataScanComplete))return false;
            string temp=dataCachePath+".tmp";
            try
            {
                var allApps=inventory.Concat(archivedDataApps).GroupBy(AppKey,StringComparer.OrdinalIgnoreCase).Select(g=>g.OrderByDescending(a=>a.IsInstalled).First()).ToList();
                long deltaLength=0;try{if(File.Exists(dataCacheDeltaPath))deltaLength=new FileInfo(dataCacheDeltaPath).Length;}catch{}
                bool rewrite=pendingCacheFullRewrite||!File.Exists(dataCachePath)||deltaLength>=5L*1024*1024;
                if(rewrite)
                {
                    int total=allApps.Sum(a=>a.DataItems.Count),done=0,stride=Math.Max(1,total/100);string dir=Path.GetDirectoryName(dataCachePath);Directory.CreateDirectory(dir);
                    using(var writer=new StreamWriter(temp,false,new System.Text.UTF8Encoding(false))){writer.WriteLine("KOKA-DATA-CACHE\t1");writer.WriteLine("S\t"+CacheEncode(cachedInventorySignature??""));writer.WriteLine("R\t"+(installedDataScanRunning&&!finalCacheWriteRunning?"INCOMPLETE":"COMPLETE"));for(int appIndex=0;appIndex<allApps.Count;appIndex++){AppInfo app=allApps[appIndex];int before=done;WriteCachedAppWithProgress(writer,app,ref done,total,stride,progress);if(app.DataItems.Count==0&&progress!=null)progress(700+(int)((appIndex+1)*280L/Math.Max(1,allApps.Count)),"正在整理缓存（"+(appIndex+1)+" / "+allApps.Count+"）…");}}
                    if(progress!=null)progress(995,"正在安全替换旧缓存…");if(File.Exists(dataCachePath))File.Replace(temp,dataCachePath,null);else File.Move(temp,dataCachePath);if(File.Exists(dataCacheDeltaPath))File.Delete(dataCacheDeltaPath);
                }
                else
                {
                    var selected=allApps.Where(a=>{string prior;return !pendingCacheBaseline.TryGetValue(AppKey(a),out prior)||!String.Equals(prior,CacheAppSignature(a),StringComparison.Ordinal);}).ToList();var currentKeys=new HashSet<string>(allApps.Select(AppKey),StringComparer.OrdinalIgnoreCase);var removed=pendingCacheBaseline.Keys.Where(key=>!currentKeys.Contains(key)).ToList();Directory.CreateDirectory(Path.GetDirectoryName(dataCachePath));
                    using(var writer=new StreamWriter(dataCacheDeltaPath,true,new System.Text.UTF8Encoding(false))){writer.WriteLine("R\tINCOMPLETE");writer.WriteLine("S\t"+CacheEncode(cachedInventorySignature??""));for(int i=0;i<removed.Count;i++)writer.WriteLine("X\t"+CacheEncode(removed[i]));for(int i=0;i<selected.Count;i++){AppInfo app=selected[i];writer.WriteLine("P\t"+CacheEncode(AppKey(app)));WriteCachedApp(writer,app);if(progress!=null)progress(700+(int)((i+1)*290L/Math.Max(1,selected.Count)),"正在追加变更缓存（"+(i+1)+" / "+selected.Count+" 个软件）…");}writer.WriteLine("R\tCOMPLETE");writer.Flush();}
                }
                pendingCacheBaseline.Clear();pendingCacheFullRewrite=false;dataCacheLoaded=true;return true;
            }catch{try{if(File.Exists(temp))File.Delete(temp);}catch{}return false;}
        }
        void WriteCachedAppWithProgress(StreamWriter writer,AppInfo app,ref int done,int total,int stride,Action<int,string> progress)
        {
            string key=AppKey(app);writer.WriteLine("A\t"+CacheEncode(key)+"\t"+CacheEncode(app.Name)+"\t"+CacheEncode(app.Version)+"\t"+CacheEncode(app.Publisher)+"\t"+CacheEncode(app.Location)+"\t"+app.IsInstalled);
            foreach(DataItem item in app.DataItems){Candidate c=item.RemovalCandidate??CandidateFromData(item.Kind,item.Path);item.RemovalCandidate=c;if(String.IsNullOrEmpty(item.Fingerprint))item.Fingerprint=GetDataItemFingerprint(item);writer.WriteLine("D\t"+CacheEncode(key)+"\t"+CacheEncode(item.Kind)+"\t"+CacheEncode(item.Path)+"\t"+item.Size+"\t"+c.Registry+"\t"+c.IsFile+"\t"+(int)c.Hive+"\t"+(int)c.View+"\t"+CacheEncode(c.Key)+"\t"+CacheEncode(item.Fingerprint));done++;if(progress!=null&&(done%stride==0||done==total))progress(total==0?700:600+(int)(done*100L/total),"正在整理缓存数据（"+done+" / "+total+"）…");}
        }
        void StartDataMonitoringAsync()
        {
            if(dataMonitoringStarted)return;dataMonitoringStarted=true;dataMonitoringStopped=false;
            dataRescanTimer=new System.Windows.Forms.Timer{Interval=1500};dataRescanTimer.Tick+=(s,e)=>{dataRescanTimer.Stop();if(dataCacheDirty&&activeTab==2)countLabel.Text="数据有变化；点击扫描以更新缓存。";};
            string[] roots={Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData)};
            registryPollTimer=new System.Threading.Timer(CheckRegistryChanges,null,20000,20000);
            Task.Run(()=>
            {
                var created=new List<FileSystemWatcher>();
                foreach(string root in roots.Where(x=>!String.IsNullOrWhiteSpace(x)&&Directory.Exists(x)).Distinct(StringComparer.OrdinalIgnoreCase))
                {
                    try
                    {
                        var watcher=new FileSystemWatcher(root){IncludeSubdirectories=true,NotifyFilter=NotifyFilters.FileName|NotifyFilters.DirectoryName|NotifyFilters.LastWrite|NotifyFilters.Size,InternalBufferSize=32768};
                        watcher.Created+=OnWatchedFileChange;watcher.Changed+=OnWatchedFileChange;watcher.Deleted+=OnWatchedFileChange;watcher.Renamed+=OnWatchedFileRename;watcher.Error+=OnWatchedFileError;
                        watcher.EnableRaisingEvents=true;created.Add(watcher);
                    }
                    catch { }
                }
                try
                {
                    BeginInvoke((Action)delegate
                    {
                        if(dataMonitoringStopped||IsDisposed||Disposing){foreach(FileSystemWatcher watcher in created)try{watcher.EnableRaisingEvents=false;watcher.Dispose();}catch{}return;}
                        dataWatchers.AddRange(created);
                    });
                }
                catch { foreach(FileSystemWatcher watcher in created)try{watcher.EnableRaisingEvents=false;watcher.Dispose();}catch{} }
            });
        }
        void OnWatchedFileChange(object sender,FileSystemEventArgs e){MarkDataChanged(e.FullPath);}
        void OnWatchedFileRename(object sender,RenamedEventArgs e){MarkDataChanged(e.FullPath);MarkDataChanged(e.OldFullPath);}
        void OnWatchedFileError(object sender,ErrorEventArgs e){MarkDataChanged(null);}
        bool IsDataCachePath(string path){if(String.IsNullOrWhiteSpace(path)||String.IsNullOrWhiteSpace(dataCachePath))return false;try{string full=Path.GetFullPath(path),cacheDirectory=Path.GetFullPath(Path.GetDirectoryName(dataCachePath));return IsPathWithin(full,cacheDirectory);}catch{return false;}}
        void MarkDataChanged(string path)
        {
            try
            {
                if(IsDisposed||!IsHandleCreated||IsDataCachePath(path))return;
                BeginInvoke((Action)delegate
                {
                    dataCacheDirty=true;
                    dataChangeGeneration++;
                    if(activeTab==2)countLabel.Text="数据已发生变化；点击扫描以更新缓存。";
                });
            }
            catch{}
        }
        static bool IsPathWithin(string path,string root){if(String.IsNullOrEmpty(path)||String.IsNullOrEmpty(root))return false;string prefix=root.TrimEnd(Path.DirectorySeparatorChar,Path.AltDirectorySeparatorChar)+Path.DirectorySeparatorChar;return String.Equals(path,root,StringComparison.OrdinalIgnoreCase)||path.StartsWith(prefix,StringComparison.OrdinalIgnoreCase);}
        void CheckRegistryChanges(object state)
        {
            if(Interlocked.Exchange(ref registryPollRunning,1)!=0)return;
            try{string signature=ReadRegistrySignature();if(!IsDisposed&&IsHandleCreated)BeginInvoke((Action)delegate{if(dataCacheLoading||appsLoading||installedDataScanRunning)return;if(String.Equals(signature,lastRegistrySignature,StringComparison.OrdinalIgnoreCase))return;lastRegistrySignature=signature;dataCacheDirty=true;dataChangeGeneration++;if(activeTab==2)countLabel.Text="安装清单已变化；点击扫描以更新数据。";});}catch{}finally{Interlocked.Exchange(ref registryPollRunning,0);}
        }        void StopDataMonitoring(){dataMonitoringStopped=true;if(registryPollTimer!=null){registryPollTimer.Dispose();registryPollTimer=null;}if(dataRescanTimer!=null){dataRescanTimer.Stop();dataRescanTimer.Dispose();dataRescanTimer=null;}foreach(FileSystemWatcher watcher in dataWatchers)try{watcher.EnableRaisingEvents=false;watcher.Dispose();}catch{}dataWatchers.Clear();dataMonitoringStarted=false;}        void LoadSystemFiles()
        {
            if(systemScanRunning)return;systemScanRunning=true;countLabel.Text="正在扫描 Windows 系统文件和驱动…";
            Task.Run(()=>CollectSystemFiles()).ContinueWith(task=>{try{BeginInvoke((Action)delegate{systemInventory.Clear();if(task.Status==TaskStatus.RanToCompletion)systemInventory.AddRange(task.Result);systemScanRunning=false;RenderSystemFiles();UpdateCountLabel();});}catch{systemScanRunning=false;}});
        }
        static List<SystemEntry> CollectSystemFiles()
        {
            var result=new List<SystemEntry>();var seen=new HashSet<string>(StringComparer.OrdinalIgnoreCase);string windows=Environment.GetFolderPath(Environment.SpecialFolder.Windows);string system32=Path.Combine(windows,"System32");
            AddSystemTopFiles(result,seen,system32,new[]{".dll",".exe",".sys"},"Windows 系统文件");
            string wow=Path.Combine(windows,"SysWOW64");AddSystemTopFiles(result,seen,wow,new[]{".dll",".exe"},"Windows 32 位系统文件");
            AddSystemTreeFiles(result,seen,Path.Combine(system32,"drivers"),new[]{".sys",".inf"},"设备驱动文件");
            AddSystemTreeFiles(result,seen,Path.Combine(system32,"DriverStore","FileRepository"),new[]{".sys",".inf"},"驱动程序仓库");
            result.Sort((a,b)=>String.Compare(a.Path,b.Path,StringComparison.OrdinalIgnoreCase));return result;
        }
        static void AddSystemTopFiles(List<SystemEntry> result,HashSet<string> seen,string root,string[] extensions,string kind)
        {
            if(!Directory.Exists(root))return;try{foreach(string file in Directory.GetFiles(root)){string ext=Path.GetExtension(file);if(Array.IndexOf(extensions,ext.ToLowerInvariant())<0||!seen.Add(file))continue;long size=0;bool known=false;try{size=new FileInfo(file).Length;known=true;}catch{}result.Add(new SystemEntry{Name=Path.GetFileName(file),Kind=kind,Path=file,Size=size,SizeKnown=known});}}catch{}
        }
        static void AddSystemTreeFiles(List<SystemEntry> result,HashSet<string> seen,string root,string[] extensions,string kind)
        {
            if(!Directory.Exists(root))return;var pending=new Stack<string>();pending.Push(root);while(pending.Count>0){string dir=pending.Pop();try{foreach(string file in Directory.GetFiles(dir)){if(Array.IndexOf(extensions,Path.GetExtension(file).ToLowerInvariant())<0||!seen.Add(file))continue;long size=0;bool known=false;try{size=new FileInfo(file).Length;known=true;}catch{}result.Add(new SystemEntry{Name=Path.GetFileName(file),Kind=kind,Path=file,Size=size,SizeKnown=known});}foreach(string sub in Directory.GetDirectories(dir))try{if((File.GetAttributes(sub)&FileAttributes.ReparsePoint)==0)pending.Push(sub);}catch{}}catch{}}
        }
        void RenderSystemFiles()
        {
            systemFiles.BeginUpdate();systemFiles.Items.Clear();string q=filterIsPlaceholder?"":filter.Text.Trim();foreach(SystemEntry file in systemInventory){if(q.Length>0&&file.Name.IndexOf(q,StringComparison.OrdinalIgnoreCase)<0&&file.Path.IndexOf(q,StringComparison.OrdinalIgnoreCase)<0&&file.Kind.IndexOf(q,StringComparison.OrdinalIgnoreCase)<0)continue;var row=new ListViewItem(file.Name){Tag=file};row.SubItems.Add(file.Kind);row.SubItems.Add(file.SizeKnown?FormatSize(file.Size):"未知");row.SubItems.Add(file.Path);systemFiles.Items.Add(row);}systemFiles.EndUpdate();FitFillerColumn(systemFiles,systemFiller);
        }
        void RenderDataTree()
        {
            DataTreeRow previousTop=dataTree.Items.Count>0?(dataTree.TopItem==null?null:dataTree.TopItem.Tag as DataTreeRow):null;string previousTopApp=previousTop==null?null:AppKey(previousTop.App);string previousTopPath=previousTop==null||previousTop.Entry==null?null:previousTop.Entry.Path;bool previousTopIsApp=previousTop!=null&&previousTop.IsApp;
            dataTree.BeginUpdate();dataTree.Items.Clear();string q=filterIsPlaceholder?"":filter.Text.Trim();
            // The data page is for data owned by currently installed applications only.
            // Uninstalled applications with residue stay visible in the All page.
            var apps=inventory.Where(a=>a.IsInstalled).OrderBy(a=>a.Name,StringComparer.CurrentCultureIgnoreCase);
            foreach(AppInfo app in apps)
            {
                if(q.Length>0&&app.Name.IndexOf(q,StringComparison.OrdinalIgnoreCase)<0&&!app.DataItems.Any(c=>(c.Path??"").IndexOf(q,StringComparison.OrdinalIgnoreCase)>=0))continue;
                string key=AppKey(app);bool expanded=expandedDataApps.Contains(key);var root=new ListViewItem((app.DataItems.Count==0?"   ":(expanded?"▾ ":"▸ "))+app.Name,EnsureAppIcon(app)){Tag=new DataTreeRow{App=app,IsApp=true}};root.SubItems.Add(GetSoftwareType(app));root.SubItems.Add(app.DataItems.Count==0?"未发现关联数据":app.DataItems.Count+" 项数据");dataTree.Items.Add(root);
                if(!expanded)continue;
                int visibleChildren=app.DataItems.Count;int animatedCount;if(expandedDataRowsVisible.TryGetValue(key,out animatedCount))visibleChildren=Math.Min(visibleChildren,animatedCount);
                for(int i=0;i<visibleChildren;i++){DataItem entry=app.DataItems[i];string location=entry.Path??"";string label=entry.Kind=="注册表项"?"注册表项："+LastPathPart(location):Path.GetFileName(location.TrimEnd('\\','/'));if(String.IsNullOrWhiteSpace(label))label=location;var child=new ListViewItem((i==visibleChildren-1?"└─ ":"├─ ")+label){Tag=new DataTreeRow{App=app,Entry=entry}};child.SubItems.Add(entry.Kind??"数据");child.SubItems.Add(location);dataTree.Items.Add(child);}
            }
            dataTree.EndUpdate();FitFillerColumn(dataTree,dataFiller);
            if(previousTopApp!=null){ListViewItem restore=null;foreach(ListViewItem item in dataTree.Items){DataTreeRow row=item.Tag as DataTreeRow;if(row==null||!String.Equals(AppKey(row.App),previousTopApp,StringComparison.OrdinalIgnoreCase))continue;if((previousTopIsApp&&row.IsApp)||(!previousTopIsApp&&row.Entry!=null&&String.Equals(row.Entry.Path,previousTopPath,StringComparison.OrdinalIgnoreCase))){restore=item;break;}if(row.IsApp)restore=item;}if(restore!=null)try{dataTree.TopItem=restore;}catch{}}
            UpdatePinnedDataHeader();
        }
        void UpdatePinnedDataHeader()
        {
            AppInfo app=String.IsNullOrEmpty(pinnedDataAppKey)?null:inventory.Concat(archivedDataApps).FirstOrDefault(a=>String.Equals(AppKey(a),pinnedDataAppKey,StringComparison.OrdinalIgnoreCase)&&expandedDataApps.Contains(pinnedDataAppKey)&&a.DataItems.Count>=20);
            if(activeTab!=2||app==null){pinnedDataHeader.Visible=false;return;}pinnedDataLabel.Text=app.Name+"  ·  "+app.DataItems.Count+" 项数据";try{pinnedDataIcon.Image=appIcons.Images[EnsureAppIcon(app)];}catch{pinnedDataIcon.Image=null;}pinnedDataHeader.Visible=true;pinnedDataHeader.BringToFront();
        }        void DataTreeMouseClick(object sender,MouseEventArgs e)
        {
            if(e.Button!=MouseButtons.Left)return;ListViewItem item=dataTree.GetItemAt(e.X,e.Y);DataTreeRow row=item==null?null:item.Tag as DataTreeRow;if(row==null||!row.IsApp||row.App.DataItems.Count==0||e.X>dataTree.Columns[0].Width)return;string key=AppKey(row.App);if(dataExpandTimer!=null){dataExpandTimer.Stop();dataExpandTimer.Dispose();dataExpandTimer=null;}dataExpandKey=key;bool closing=expandedDataApps.Contains(key);if(closing){int visible;if(!expandedDataRowsVisible.TryGetValue(key,out visible))visible=row.App.DataItems.Count;expandedDataRowsVisible[key]=visible;dataExpandTarget=0;if(String.Equals(pinnedDataAppKey,key,StringComparison.OrdinalIgnoreCase))pinnedDataAppKey=null;}else{expandedDataApps.Add(key);expandedDataRowsVisible[key]=0;dataExpandTarget=row.App.DataItems.Count;pinnedDataAppKey=row.App.DataItems.Count>=20?key:null;}dataExpandTimer=new System.Windows.Forms.Timer{Interval=16};dataExpandTimer.Tick+=(s,ev)=>{int count;if(!expandedDataRowsVisible.TryGetValue(dataExpandKey,out count))count=0;int delta=Math.Max(1,Math.Max(dataExpandTarget,count)/9);count=dataExpandTarget>count?Math.Min(dataExpandTarget,count+delta):Math.Max(dataExpandTarget,count-delta);expandedDataRowsVisible[dataExpandKey]=count;bool complete=count==dataExpandTarget;if(complete&&count==0){expandedDataApps.Remove(dataExpandKey);expandedDataRowsVisible.Remove(dataExpandKey);}RenderDataTree();if(complete){dataExpandTimer.Stop();dataExpandTimer.Dispose();dataExpandTimer=null;}};dataExpandTimer.Start();
        }
        void DataTreeMouseUp(object sender,MouseEventArgs e)
        {
            if(e.Button!=MouseButtons.Right)return;ListViewItem item=dataTree.GetItemAt(e.X,e.Y);if(item==null)return;DataTreeRow row=item.Tag as DataTreeRow;if(row==null||row.IsApp||row.Entry==null||row.Entry.RemovalCandidate==null)return;dataTree.SelectedItems.Clear();item.Selected=true;deleteDataMenu.Enabled=true;dataMenu.Show(dataTree,e.Location);
        }
        void DeleteSelectedDataItem(object sender,EventArgs e)
        {
            if(dataTree.SelectedItems.Count==0)return;DataTreeRow row=dataTree.SelectedItems[0].Tag as DataTreeRow;if(row==null||row.IsApp||row.Entry==null||row.Entry.RemovalCandidate==null)return;Candidate candidate=row.Entry.RemovalCandidate;string what=candidate.Registry?"注册表项":candidate.IsFile?"文件":"文件夹及其内容";string warning=candidate.Registry?"注册表项会先导出备份。":"文件或文件夹将被永久删除。";if(MessageBox.Show("确定删除这个数据项吗？\r\n\r\n类型："+what+"\r\n位置："+candidate.Path+"\r\n\r\n"+warning,"删除软件数据",MessageBoxButtons.YesNo,MessageBoxIcon.Warning)!=DialogResult.Yes)return;DeleteDataCandidate(row.App,candidate);
        }
        void DeleteDataCandidate(AppInfo app,Candidate candidate)
        {
            if(installedDataScanRunning)return;
            ShowLoading("正在删除所选数据并复查剩余项目…");Task.Run(()=>CleanAndRescan(app,new List<Candidate>{candidate},false,(path,done,total)=>UpdateLoadingProgress(total==0?0:(int)(done*1000L/total),"正在删除并复查："+path))).ContinueWith(task=>{try{BeginInvoke((Action)delegate{HideLoading();if(task.Status!=TaskStatus.RanToCompletion){MessageBox.Show("删除失败，请重新扫描确认数据状态。","删除失败",MessageBoxButtons.OK,MessageBoxIcon.Error);return;}CleanupReport result=task.Result;app.Residues=result.Remaining;ResidueReport report=result.RemainingSummary??new ResidueReport();app.DataItems=report.Entries.Select(CreateDataItem).ToList();app.SizeBytes=report.TotalSizeBytes;app.HasKnownSize=report.Complete;app.SizeCalculationComplete=true;if(!app.IsInstalled&&app.DataItems.Count==0){inventory.Remove(app);archivedDataApps.RemoveAll(a=>AppKey(a)==AppKey(app));}RenderDataTree();UpdateCountLabel();if(result.Errors.Length>0)MessageBox.Show("所选项目处理后仍有未完成项：\r\n"+result.Errors,"部分删除",MessageBoxButtons.OK,MessageBoxIcon.Warning);});}catch{HideLoading();}});
        }        static string LastPathPart(string path){if(String.IsNullOrWhiteSpace(path))return "";string[] parts=path.TrimEnd('\\').Split('\\');return parts.Length==0?path:parts[parts.Length-1];}
        static string GetSoftwareType(AppInfo app)
        {
            if(app.Residues.Any(c=>c.Registry&&c.Key!=null&&c.Key.IndexOf("\\Services\\",StringComparison.OrdinalIgnoreCase)>=0))return "服务";
            if(app.Residues.Any(c=>!c.Registry&&String.Equals(Path.GetExtension(c.Path),".sys",StringComparison.OrdinalIgnoreCase)))return "驱动";
            if((app.Command??"").IndexOf("msiexec",StringComparison.OrdinalIgnoreCase)>=0)return "MSI 软件";
            return app.Type??"软件";
        }
        static string GetDataType(Candidate entry)
        {
            if(entry.Registry)return "注册表";if(!entry.IsFile&&Directory.Exists(entry.Path))return "文件夹";string ext=Path.GetExtension(entry.Path??"");return String.IsNullOrEmpty(ext)?"数据文件":ext.TrimStart('.').ToUpperInvariant()+" 文件";
        }
        void ReadApps(RegistryHive hive, RegistryView view,List<AppInfo> targetInventory,CancellationToken cancellationToken)
        {
            const string rootPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
            try { using (var root = RegistryKey.OpenBaseKey(hive, view).OpenSubKey(rootPath)) { if (root == null) return; foreach (var name in root.GetSubKeyNames()) try { cancellationToken.ThrowIfCancellationRequested();using (var key = root.OpenSubKey(name)) { if (key == null) continue; var n = Convert.ToString(key.GetValue("DisplayName")); var cmd = Convert.ToString(key.GetValue("UninstallString")); int system;Int32.TryParse(Convert.ToString(key.GetValue("SystemComponent",0)),out system);if (String.IsNullOrWhiteSpace(n) || String.IsNullOrWhiteSpace(cmd) || system == 1 || !String.IsNullOrEmpty(Convert.ToString(key.GetValue("ParentKeyName")))) continue; long size; Int64.TryParse(Convert.ToString(key.GetValue("EstimatedSize")),out size); var item = new AppInfo { Name=n.Trim(), Version=Convert.ToString(key.GetValue("DisplayVersion")), Publisher=Convert.ToString(key.GetValue("Publisher")), Location=Environment.ExpandEnvironmentVariables(Convert.ToString(key.GetValue("InstallLocation")) ?? ""), Command=cmd, DisplayIcon=Environment.ExpandEnvironmentVariables(Convert.ToString(key.GetValue("DisplayIcon")) ?? ""), SizeBytes=size>0?size*1024:0, HasKnownSize=size>0, SizeCalculationComplete=size>0 }; bool dup=false; foreach(var old in targetInventory) if(String.Equals(old.Name,item.Name,StringComparison.OrdinalIgnoreCase) && old.Version==item.Version && old.Publisher==item.Publisher) dup=true; if(!dup) targetInventory.Add(item); } } catch(OperationCanceledException){throw;}catch {} } } catch(OperationCanceledException){throw;}catch {}
        }
        void ShowApps()
        {
            if(appsLoading)return;
            software.Visible=activeTab==0||activeTab==1;stateFilterBox.Visible=activeTab==0;scanDataButton.Visible=activeTab==2;dataTree.Visible=activeTab==2;systemFiles.Visible=activeTab==3;
            if(activeTab==2){if(!dataCacheLoaded){if(!dataCacheLoading)LoadDataCacheForDataTab();return;}RenderDataTree();UpdateCountLabel();if(dataCacheValidationComplete&&!dataCacheDirty)countLabel.Text+=" · 缓存扫描已完成";return;}
            if(activeTab==3){RenderSystemFiles();if(systemInventory.Count==0&&!systemScanRunning)LoadSystemFiles();else if(!systemScanRunning)countLabel.Text="系统文件和驱动文件："+systemInventory.Count+" 个";return;}
            software.BeginUpdate(); software.Items.Clear(); string q=filterIsPlaceholder?"":filter.Text.Trim();
            var displayed=inventory.FindAll(app=>(app.IsInstalled||app.Residues.Count>0)&&(activeTab!=1||app.IsInstalled)&&(activeTab!=2||!app.IsInstalled)&&(activeTab!=0||allFilterMode==0||(allFilterMode==1&&app.IsInstalled)||(allFilterMode==2&&!app.IsInstalled&&app.Residues.Count>0))&&(q.Length==0||(app.Name??"").IndexOf(q,StringComparison.OrdinalIgnoreCase)>=0||(app.Publisher??"").IndexOf(q,StringComparison.OrdinalIgnoreCase)>=0));
            displayed.Sort((a,b)=>{if(sortMode==0)return String.Compare(a.Name,b.Name,StringComparison.CurrentCultureIgnoreCase);bool ak=a.SizeCalculationComplete&&a.HasKnownSize,bk=b.SizeCalculationComplete&&b.HasKnownSize;if(ak!=bk)return ak?-1:1;int size=sortMode==1?b.SizeBytes.CompareTo(a.SizeBytes):a.SizeBytes.CompareTo(b.SizeBytes);return size!=0?size:String.Compare(a.Name,b.Name,StringComparison.CurrentCultureIgnoreCase);});
            foreach(var app in displayed)
            {
                app.IconKey=EnsureAppIcon(app);
                var row=new ListViewItem(app.Name,app.IconKey){Tag=app};
                row.SubItems.Add(GetSoftwareType(app));row.SubItems.Add(SizeDisplay(app));
                row.SubItems.Add(app.IsInstalled?(app.Residues.Count>0?"已安装 · 扫描到 "+app.Residues.Count+" 项":"已安装"):(app.Residues.Count>0?"已卸载 · 有残留":"已卸载 · 待检查残留"));
                row.SubItems.Add(app.Version??""); row.SubItems.Add(app.Publisher??"");
                row.SubItems.Add(app.IsInstalled?(app.Location??""):(FirstResiduePath(app)??app.Location??""));
                software.Items.Add(row);
            }
            software.EndUpdate();FitFillerColumn(software,softwareFiller);
            UpdateCountLabel();
            // 启动和页面切换期间只显示注册表大小估算；完整目录大小计算不自动运行。
        }
        void SelectApp(object sender, EventArgs e)
        {
            current=software.SelectedItems.Count==0?null:software.SelectedItems[0].Tag as AppInfo;
            if(current!=null&&software.SelectedItems.Count>0){ListViewItem row=software.SelectedItems[0];row.SubItems[3].Text=current.IsInstalled?(current.Residues.Count>0?"已安装 · 扫描到 "+current.Residues.Count+" 项":"已安装"):(current.Residues.Count>0?"已卸载 · 有残留":"已卸载 · 待检查残留");}
        }
        static void DrawRefreshIcon(Graphics graphics,Rectangle bounds,Color color)
        {
            graphics.SmoothingMode=System.Drawing.Drawing2D.SmoothingMode.AntiAlias;float x=bounds.Left+(bounds.Width-17)/2f,y=bounds.Top+(bounds.Height-17)/2f;
            using(var pen=new Pen(color,2.1f){StartCap=System.Drawing.Drawing2D.LineCap.Round,EndCap=System.Drawing.Drawing2D.LineCap.Round})graphics.DrawArc(pen,x+2,y+2,13,13,45,285);
            PointF[] arrow={new PointF(x+11,y),new PointF(x+17,y+1),new PointF(x+13,y+6)};using(var brush=new SolidBrush(color))graphics.FillPolygon(brush,arrow);
        }
        void LoadUserSettings()
        {
            settingsPath=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"koka","settings.ini");try{darkTheme=true;if(!File.Exists(settingsPath))return;var values=new Dictionary<string,string>(StringComparer.OrdinalIgnoreCase);foreach(string line in File.ReadAllLines(settingsPath)){int split=line.IndexOf('=');if(split>0)values[line.Substring(0,split).Trim()]=line.Substring(split+1).Trim();}int x,y,w,h;if(Int32.TryParse(values.ContainsKey("x")?values["x"]:null,out x)&&Int32.TryParse(values.ContainsKey("y")?values["y"]:null,out y)&&Int32.TryParse(values.ContainsKey("width")?values["width"]:null,out w)&&Int32.TryParse(values.ContainsKey("height")?values["height"]:null,out h)){savedBounds=new Rectangle(x,y,w,h);hasSavedBounds=true;}foreach(var pair in values)if(pair.Key.StartsWith("col.",StringComparison.OrdinalIgnoreCase)){int width;if(Int32.TryParse(pair.Value,out width)&&width>=40)savedColumnWidths[pair.Key]=width;}}catch{}
        }
        void SaveUserSettings()
        {
            try{Rectangle bounds=WindowState==FormWindowState.Normal?Bounds:RestoreBounds;Directory.CreateDirectory(Path.GetDirectoryName(settingsPath));var lines=new List<string>{"x="+bounds.X,"y="+bounds.Y,"width="+bounds.Width,"height="+bounds.Height};AppendColumnWidths(lines,"software",software,softwareFiller);AppendColumnWidths(lines,"data",dataTree,dataFiller);AppendColumnWidths(lines,"system",systemFiles,systemFiller);File.WriteAllLines(settingsPath,lines);}catch{}
        }
        void AppendColumnWidths(List<string> lines,string name,ListView view,ColumnHeader filler){if(view==null)return;for(int i=0;i<view.Columns.Count;i++)if(view.Columns[i]!=filler)lines.Add("col."+name+"."+i+"="+view.Columns[i].Width);}
        void ApplySavedColumnWidths(string name,ListView view,ColumnHeader filler){for(int i=0;i<view.Columns.Count;i++){int width;if(view.Columns[i]!=filler&&savedColumnWidths.TryGetValue("col."+name+"."+i,out width))view.Columns[i].Width=width;}FitFillerColumn(view,filler);}        void ApplyTheme()
        {
            SetPalette(ThemePalette(darkTheme));PaintTheme();
        }
        Color[] ThemePalette(bool dark){return new[]{Color.FromArgb(15,20,28),Color.FromArgb(24,32,43),Color.FromArgb(27,36,49),Color.FromArgb(239,243,250),Color.FromArgb(181,192,207),Color.FromArgb(42,55,72),Color.FromArgb(65,139,245),Color.FromArgb(39,61,91)};}
        void SetPalette(Color[] colors){pageColor=colors[0];surfaceColor=colors[1];alternateColor=colors[2];textColor=colors[3];mutedColor=colors[4];borderColor=colors[5];accentColor=colors[6];selectedColor=colors[7];}
        void PaintTheme()
        {
            ApplyThemeToControls(this);foreach(Form child in OwnedForms)if(child!=this&&!child.IsDisposed){ApplyThemeToControls(child);NativeTheme.SetForm(child,true,surfaceColor,textColor,borderColor);}UpdateTabStyles();appMenu.BackColor=surfaceColor;appMenu.ForeColor=textColor;appMenu.Renderer=new ToolStripProfessionalRenderer(new KokaColorTable(true));sortMenu.BackColor=surfaceColor;sortMenu.ForeColor=textColor;sortMenu.Renderer=new ToolStripProfessionalRenderer(new KokaColorTable(true));dataMenu.BackColor=surfaceColor;dataMenu.ForeColor=textColor;dataMenu.Renderer=new ToolStripProfessionalRenderer(new KokaColorTable(true));stateFilterMenu.BackColor=surfaceColor;stateFilterMenu.ForeColor=textColor;stateFilterMenu.Renderer=new ToolStripProfessionalRenderer(new KokaColorTable(true));NativeTheme.SetForm(this,true,surfaceColor,textColor,borderColor);Invalidate(true);
        }
        void ApplyThemeToControls(Control root)
        {
            if(root is Form)NativeTheme.SetForm((Form)root,darkTheme,surfaceColor,textColor,borderColor);
            if(root is Form||root is TableLayoutPanel||root is FlowLayoutPanel)root.BackColor=pageColor;
            else if(root is Panel)root.BackColor=surfaceColor;
            if(root is Label){root.ForeColor=textColor;}
            else if(root is TextBox){root.BackColor=surfaceColor;root.ForeColor=filterIsPlaceholder&&root==filter?mutedColor:textColor;}
            else if(root is ComboBox){root.BackColor=surfaceColor;root.ForeColor=textColor;if(!root.IsHandleCreated)root.HandleCreated+=delegate{NativeTheme.SetControl(root,darkTheme);};NativeTheme.SetControl(root,darkTheme);}
            else if(root is ListBox){ListBox box=(ListBox)root;box.BackColor=surfaceColor;box.ForeColor=textColor;box.BorderStyle=BorderStyle.FixedSingle;if(!box.IsHandleCreated)box.HandleCreated+=delegate{NativeTheme.SetControl(box,darkTheme);};NativeTheme.SetControl(box,darkTheme);}
            else if(root is ListView){root.BackColor=surfaceColor;root.ForeColor=textColor;if(!root.IsHandleCreated)root.HandleCreated+=delegate{NativeTheme.SetControl(root,darkTheme);};NativeTheme.SetControl(root,darkTheme);}
            else if(root is Button){Button button=(Button)root;button.FlatStyle=FlatStyle.Flat;int border=Equals(button.Tag,"refresh")?1:0;button.FlatAppearance.BorderSize=border;if(border>0)button.FlatAppearance.BorderColor=borderColor;button.FlatAppearance.MouseOverBackColor=alternateColor;button.FlatAppearance.MouseDownBackColor=selectedColor;button.BackColor=surfaceColor;button.ForeColor=Equals(button.Tag,"refresh")?accentColor:textColor;}
            foreach(Control child in root.Controls)ApplyThemeToControls(child);
        }
        void UpdateTabStyles()
        {
            Button[] buttons={allTab,installedTab,uninstalledTab,systemTab};for(int i=0;i<buttons.Length;i++){bool selected=i==activeTab;buttons[i].BackColor=selected?accentColor:pageColor;buttons[i].ForeColor=selected?Color.White:mutedColor;buttons[i].FlatAppearance.BorderSize=0;buttons[i].FlatAppearance.MouseOverBackColor=selected?accentColor:alternateColor;buttons[i].FlatAppearance.MouseDownBackColor=selected?accentColor:alternateColor;}
        }
        void ConfigureTab(Button button,string text,int index){button.Text=text;button.Width=112;button.Height=36;button.FlatStyle=FlatStyle.Flat;button.FlatAppearance.BorderSize=0;button.Margin=new Padding(0,0,8,0);button.Cursor=Cursors.Hand;button.Font=new Font("Microsoft YaHei UI",9.5F,FontStyle.Bold);}
        Control PageControl(int index){return index==2?dataTree:index==3?systemFiles:software;}
        void SetTab(int index)
        {
            if(index==activeTab)return;if(pageSwitchTimer!=null){pageSwitchTimer.Stop();pageSwitchTimer.Dispose();pageSwitchTimer=null;if(pageSwitchControl!=null&&!pageSwitchControl.IsDisposed)pageSwitchControl.Dock=DockStyle.Fill;pageSwitchControl=null;}
            activeTab=index;if(index!=2)pinnedDataHeader.Visible=false;UpdateTabStyles();ShowApps();Control incoming=PageControl(index);if(incoming==null||!incoming.Visible||incoming.IsDisposed)return;pageSwitchControl=incoming;pageSwitchTarget=incoming.Bounds;incoming.Dock=DockStyle.None;incoming.Bounds=new Rectangle(pageSwitchTarget.Right,pageSwitchTarget.Y,pageSwitchTarget.Width,pageSwitchTarget.Height);incoming.BringToFront();if(index==2)pinnedDataHeader.BringToFront();pageSwitchTimer=new System.Windows.Forms.Timer{Interval=15};pageSwitchTimer.Tick+=(s,e)=>{if(pageSwitchControl==null||pageSwitchControl.IsDisposed){pageSwitchTimer.Stop();pageSwitchTimer.Dispose();pageSwitchTimer=null;return;}int next=pageSwitchControl.Left-Math.Max(24,pageSwitchTarget.Width/9);if(next<=pageSwitchTarget.Left){pageSwitchControl.Bounds=pageSwitchTarget;pageSwitchControl.Dock=DockStyle.Fill;pageSwitchControl.BringToFront();if(activeTab==2)pinnedDataHeader.BringToFront();pageSwitchTimer.Stop();pageSwitchTimer.Dispose();pageSwitchTimer=null;pageSwitchControl=null;return;}pageSwitchControl.Left=next;};pageSwitchTimer.Start();
        }
        void DrawSearchBox(Graphics graphics,Rectangle bounds)
        {
            graphics.SmoothingMode=System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
            Rectangle frame=new Rectangle(bounds.Left+1,bounds.Top+1,bounds.Width-3,bounds.Height-3);
            using(var path=RoundedRectangle(frame,7))using(var brush=new SolidBrush(surfaceColor))graphics.FillPath(brush,path);
            using(var path=RoundedRectangle(frame,7))using(var pen=new Pen(filter.Focused?accentColor:borderColor,filter.Focused?1.5f:1f))graphics.DrawPath(pen,path);
            float x=13,y=bounds.Height/2f-4;using(var pen=new Pen(mutedColor,1.7f)){graphics.DrawEllipse(pen,x,y,8,8);graphics.DrawLine(pen,x+7,y+7,x+12,y+12);}
        }
        static System.Drawing.Drawing2D.GraphicsPath RoundedRectangle(Rectangle bounds,int radius)
        {
            int d=radius*2;var path=new System.Drawing.Drawing2D.GraphicsPath();path.AddArc(bounds.Left,bounds.Top,d,d,180,90);path.AddArc(bounds.Right-d,bounds.Top,d,d,270,90);path.AddArc(bounds.Right-d,bounds.Bottom-d,d,d,0,90);path.AddArc(bounds.Left,bounds.Bottom-d,d,d,90,90);path.CloseFigure();return path;
        }
        static void FitFillerColumn(ListView view,ColumnHeader filler)
        {
            if(view==null||filler==null||view.IsDisposed||view.Columns.Count==0)return;int occupied=0;foreach(ColumnHeader column in view.Columns)if(column!=filler)occupied+=column.Width;int width=Math.Max(0,view.ClientSize.Width-occupied);if(filler.Width!=width)filler.Width=width;
        }

        void DrawSortBox(Graphics graphics,Rectangle bounds)
        {
            if(bounds.Width<=0||bounds.Height<=0)return;graphics.SmoothingMode=System.Drawing.Drawing2D.SmoothingMode.AntiAlias;using(var brush=new SolidBrush(surfaceColor))graphics.FillRectangle(brush,bounds);using(var pen=new Pen(borderColor,1f))graphics.DrawRectangle(pen,0,0,bounds.Width-1,bounds.Height-1);Point mid=new Point(bounds.Right-16,bounds.Height/2);using(var pen=new Pen(mutedColor,1.8f)){graphics.DrawLine(pen,mid.X-4,mid.Y-2,mid.X,mid.Y+2);graphics.DrawLine(pen,mid.X,mid.Y+2,mid.X+4,mid.Y-2);}
        }
        void ShowSortMenu(object sender,EventArgs e){sortMenu.Show(sortBox,0,sortBox.Height+2);}
        void DrawListHeader(object sender,DrawListViewColumnHeaderEventArgs e)
        {
            using(var brush=new SolidBrush(darkTheme?Color.FromArgb(31,42,57):Color.FromArgb(238,242,248)))e.Graphics.FillRectangle(brush,e.Bounds);using(var pen=new Pen(borderColor))e.Graphics.DrawLine(pen,e.Bounds.Left,e.Bounds.Bottom-1,e.Bounds.Right,e.Bounds.Bottom-1);TextFormatFlags flags=TextFormatFlags.VerticalCenter|TextFormatFlags.EndEllipsis|TextFormatFlags.Left;if(e.Header.TextAlign==HorizontalAlignment.Center)flags=TextFormatFlags.VerticalCenter|TextFormatFlags.EndEllipsis|TextFormatFlags.HorizontalCenter;else if(e.Header.TextAlign==HorizontalAlignment.Right)flags=TextFormatFlags.VerticalCenter|TextFormatFlags.EndEllipsis|TextFormatFlags.Right;Rectangle text=e.Bounds;text.Inflate(-10,0);using(var headerFont=new Font(Font,FontStyle.Bold))TextRenderer.DrawText(e.Graphics,e.Header.Text,headerFont,text,textColor,flags);
        }
        void DrawListSubItem(object sender,DrawListViewSubItemEventArgs e)
        {
            ListView view=(ListView)sender;bool selected=e.Item.Selected;Color fill=selected?selectedColor:(e.ItemIndex%2==0?surfaceColor:alternateColor);using(var brush=new SolidBrush(fill))e.Graphics.FillRectangle(brush,e.Bounds);using(var pen=new Pen(borderColor))e.Graphics.DrawLine(pen,e.Bounds.Left,e.Bounds.Bottom-1,e.Bounds.Right,e.Bounds.Bottom-1);Rectangle text=e.Bounds;text.Inflate(-10,0);DataTreeRow dataRow=view==dataTree?e.Item.Tag as DataTreeRow:null;bool showIcon=e.ColumnIndex==0&&(view==software||(view==dataTree&&dataRow!=null&&dataRow.IsApp));if(showIcon){try{Image image=appIcons.Images[e.Item.ImageKey];if(image!=null){e.Graphics.DrawImage(image,new Rectangle(e.Bounds.Left+5,e.Bounds.Top+(e.Bounds.Height-28)/2,28,28));text.X+=34;text.Width-=34;}}catch{}}if(view.CheckBoxes&&e.ColumnIndex==0){Rectangle check=new Rectangle(e.Bounds.Left+4,e.Bounds.Top+(e.Bounds.Height-14)/2,14,14);ControlPaint.DrawCheckBox(e.Graphics,check,e.Item.Checked?ButtonState.Checked:ButtonState.Normal);text.X+=18;text.Width-=18;}TextFormatFlags flags=TextFormatFlags.VerticalCenter|TextFormatFlags.EndEllipsis|TextFormatFlags.NoPrefix|TextFormatFlags.Left;if(e.Header.TextAlign==HorizontalAlignment.Center)flags|=TextFormatFlags.HorizontalCenter;else if(e.Header.TextAlign==HorizontalAlignment.Right)flags=TextFormatFlags.VerticalCenter|TextFormatFlags.EndEllipsis|TextFormatFlags.NoPrefix|TextFormatFlags.Right;Font itemFont=view.Font;Font emphasis=null;if(dataRow!=null&&dataRow.IsApp){emphasis=new Font(view.Font,FontStyle.Bold);itemFont=emphasis;}TextRenderer.DrawText(e.Graphics,e.SubItem.Text,itemFont,text,textColor,flags);if(emphasis!=null)emphasis.Dispose();
        }
        string AppTotalSize(List<AppInfo> apps){long total=0;foreach(AppInfo app in apps){if(!app.SizeCalculationComplete)return "计算中…";if(!app.HasKnownSize)return "未知";total+=app.SizeBytes;}return FormatSize(total);}
        string SystemTotalSize(){long total=0;foreach(SystemEntry item in systemInventory){if(!item.SizeKnown)return "未知";total+=item.Size;}return FormatSize(total);}
        void UpdateCountLabel(){var installed=inventory.FindAll(a=>a.IsInstalled);var residues=inventory.FindAll(a=>!a.IsInstalled&&a.Residues.Count>0);var installedData=installed.Where(a=>a.DataItems.Count>0).ToList();countLabel.Text=activeTab==1?"当前安装的软件数量："+installed.Count+" 个    总大小："+AppTotalSize(installed):activeTab==2?"数据来源软件："+installedData.Count+" 个    文件/注册表数据："+installedData.Sum(a=>a.DataItems.Count)+" 项    总大小："+FormatSize(installedData.SelectMany(a=>a.DataItems).Sum(i=>i.Size)):activeTab==3?"系统文件和驱动文件："+systemInventory.Count+" 个    总大小："+SystemTotalSize():"安装软件："+installed.Count+" 个    有残留的软件："+residues.Count+" 个    总大小："+AppTotalSize(installed.Concat(residues).ToList());}
        static string FormatSize(long bytes){if(bytes<0)return "未知";if(bytes<1024)return bytes+" B";if(bytes<1024*1024)return (bytes/1024.0).ToString("0.0")+" KB";if(bytes<1024L*1024*1024)return (bytes/(1024.0*1024)).ToString("0.0")+" MB";return (bytes/(1024.0*1024*1024)).ToString("0.00")+" GB";}
        static string FirstResiduePath(AppInfo app){foreach(Candidate c in app.Residues)if(!c.Registry)return c.Path;return null;}
        static string SizeDisplay(AppInfo app){if(!app.SizeCalculationComplete)return "计算中…";if(!app.HasKnownSize)return "未知";return FormatSize(app.SizeBytes);}
        string SizeFolder(AppInfo app){if(app.IsInstalled)return GetInstallFolder(app);return FirstResiduePath(app);}
        void StartSizeCalculation()
        {
            if(sizeCalcRunning)return;
            var jobs=new List<KeyValuePair<AppInfo,string[]>>();foreach(AppInfo app in inventory)if((app.IsInstalled||app.Residues.Count>0)&&!app.SizeCalculationComplete){string[] folders=app.IsInstalled?new[]{SizeFolder(app)}:app.Residues.FindAll(c=>!c.Registry).ConvertAll(c=>c.Path).ToArray();jobs.Add(new KeyValuePair<AppInfo,string[]>(app,folders));}
            if(jobs.Count==0)return;sizeCalcRunning=true;
            Task.Run(()=>{var results=new Dictionary<AppInfo,SizeResult>();object gate=new object();Parallel.ForEach(jobs,new ParallelOptions{MaxDegreeOfParallelism=Math.Max(1,Math.Min(2,Environment.ProcessorCount))},job=>{var result=new SizeResult();if(job.Value.Length==0)result.Complete=false;foreach(string folder in job.Value){if(String.IsNullOrWhiteSpace(folder)){result.Complete=false;continue;}SizeResult part=CalculateFolderSize(folder);result.Bytes+=part.Bytes;if(!part.Complete)result.Complete=false;}lock(gate)results[job.Key]=result;});return results;}).ContinueWith(task=>{try{BeginInvoke((Action)delegate{if(task.Status==TaskStatus.RanToCompletion)foreach(var pair in task.Result){pair.Key.SizeBytes=pair.Value.Bytes;pair.Key.HasKnownSize=pair.Value.Complete;pair.Key.SizeCalculationComplete=true;}else foreach(var job in jobs){job.Key.HasKnownSize=false;job.Key.SizeCalculationComplete=true;}sizeCalcRunning=false;ShowApps();});}catch{sizeCalcRunning=false;}});
        }
        static SizeResult CalculateFolderSize(string folder)
        {
            var result=new SizeResult();if(File.Exists(folder)){try{result.Bytes=new FileInfo(folder).Length;}catch{result.Complete=false;}return result;}if(!Directory.Exists(folder)){result.Complete=false;return result;}var pending=new Stack<string>();pending.Push(folder);while(pending.Count>0){string dir=pending.Pop();try{foreach(string file in Directory.EnumerateFiles(dir))try{result.Bytes+=new FileInfo(file).Length;}catch{result.Complete=false;}}catch{result.Complete=false;}try{foreach(string sub in Directory.EnumerateDirectories(dir))try{if((File.GetAttributes(sub)&FileAttributes.ReparsePoint)==0)pending.Push(sub);else result.Complete=false;}catch{result.Complete=false;}}catch{result.Complete=false;}}return result;
        }
        string EnsureAppIcon(AppInfo app)
        {
            string key=app.Name+"|"+app.Version+"|"+app.Publisher;
            if(appIcons.Images.ContainsKey(key))return key;
            appIcons.Images.Add(key,SystemIcons.Application.ToBitmap());
            if(iconLoads.Add(key))
            {
                Task.Run(()=>
                {
                    Bitmap result=null;
                    try{string path=GetIconPath(app);if(!String.IsNullOrEmpty(path)&&File.Exists(path)){using(Icon icon=Icon.ExtractAssociatedIcon(path)){if(icon!=null)result=icon.ToBitmap();}}}catch{}
                    return result;
                }).ContinueWith(task=>
                {
                    try{BeginInvoke((Action)delegate
                    {
                        iconLoads.Remove(key);
                        if(IsDisposed||task.Status!=TaskStatus.RanToCompletion||task.Result==null)return;
                        using(Bitmap bitmap=task.Result){appIcons.Images.RemoveByKey(key);appIcons.Images.Add(key,(Image)bitmap.Clone());}
                        foreach(ListViewItem row in software.Items){AppInfo item=row.Tag as AppInfo;if(item!=null&&String.Equals(row.ImageKey,key,StringComparison.OrdinalIgnoreCase))software.Invalidate(row.Bounds);}
                        foreach(ListViewItem row in dataTree.Items){DataTreeRow item=row.Tag as DataTreeRow;if(item!=null&&item.IsApp&&String.Equals(row.ImageKey,key,StringComparison.OrdinalIgnoreCase))dataTree.Invalidate(row.Bounds);}
                        if(pinnedDataIcon.Image!=null&&String.Equals(pinnedDataAppKey,AppKey(app),StringComparison.OrdinalIgnoreCase))try{pinnedDataIcon.Image=appIcons.Images[key];}catch{}
                    });}catch{if(task.Status==TaskStatus.RanToCompletion&&task.Result!=null)task.Result.Dispose();}
                });
            }
            return key;
        }        string GetIconPath(AppInfo app)
        {
            string value=(app.DisplayIcon??"").Trim();
            if(value.StartsWith("\"")){int end=value.IndexOf('"',1);if(end>1)value=value.Substring(1,end-1);}
            else { value=Regex.Replace(value,@",\s*-?\d+\s*$",""); }
            value=Environment.ExpandEnvironmentVariables(value);
            if(File.Exists(value))return value;
            if(Directory.Exists(app.Location))
            {
                string baseName=Path.GetFileName(app.Location.TrimEnd('\\','/'));
                string[] matches=Directory.GetFiles(app.Location,"*.exe",System.IO.SearchOption.TopDirectoryOnly);
                foreach(string file in matches)if(Norm(Path.GetFileNameWithoutExtension(file))==Norm(baseName))return file;
                if(matches.Length>0)return matches[0];
            }
            return null;
        }
        void SoftwareMouseUp(object sender, MouseEventArgs e)
        {
            if(e.Button!=MouseButtons.Right)return;
            ListViewItem row=software.GetItemAt(e.X,e.Y);
            if(row==null)return;
            row.Selected=true; row.Focused=true;
            appMenu.Show(software,e.Location);
        }
        void AppMenuOpening(object sender, System.ComponentModel.CancelEventArgs e)
        {
            uninstallMenu.Enabled=current!=null&&current.IsInstalled;
            openLocationMenu.Enabled=current!=null&&current.IsInstalled&&!String.IsNullOrEmpty(GetInstallFolder(current));
            detailsMenu.Enabled=current!=null;
            cleanResiduesMenu.Enabled=current!=null&&!current.IsInstalled&&current.Residues.Count>0;
            viewResiduesMenu.Enabled=current!=null&&!current.IsInstalled&&current.Residues.Count>0;
            forceRemoveMenu.Enabled=current!=null;
        }
        void ShowAppDetails(object sender,EventArgs e)
        {
            if(current==null)return;AppInfo app=current;
            var dialog=new Form{Text="koka - 软件详细信息",ClientSize=new Size(610,430),MinimumSize=new Size(560,390),StartPosition=FormStartPosition.CenterParent,FormBorderStyle=FormBorderStyle.FixedDialog,MaximizeBox=false,MinimizeBox=false,Font=Font,Icon=Icon};
            var heading=new Panel{Dock=DockStyle.Top,Height=82};heading.Paint+=(s,ev)=>{ev.Graphics.SmoothingMode=System.Drawing.Drawing2D.SmoothingMode.AntiAlias;Rectangle r=new Rectangle(0,0,heading.Width,heading.Height);using(var b=new System.Drawing.Drawing2D.LinearGradientBrush(r,Color.FromArgb(31,45,64),Color.FromArgb(23,32,44),90f))ev.Graphics.FillRectangle(b,r);using(var b=new SolidBrush(accentColor))ev.Graphics.FillRectangle(b,0,0,3,heading.Height);};
            var icon=new PictureBox{Location=new Point(18,16),Size=new Size(50,50),SizeMode=PictureBoxSizeMode.Zoom};try{icon.Image=appIcons.Images[EnsureAppIcon(app)];}catch{}var title=new Label{Text=app.Name,Location=new Point(82,14),Size=new Size(490,30),AutoEllipsis=true,Font=new Font("Microsoft YaHei UI",15F,FontStyle.Bold),ForeColor=textColor};var status=new Label{Text=app.IsInstalled?"已安装":"已卸载，存在残留",Location=new Point(84,47),AutoSize=true,ForeColor=mutedColor};heading.Controls.Add(icon);heading.Controls.Add(title);heading.Controls.Add(status);
            var table=new TableLayoutPanel{Dock=DockStyle.Fill,Padding=new Padding(22,10,22,8),ColumnCount=2,RowCount=0};table.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute,116));table.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));
            AddDetailRow(table,"发布者",app.Publisher);AddDetailRow(table,"版本",app.Version);AddDetailRow(table,"状态",app.IsInstalled?"已安装":"已卸载");AddDetailRow(table,"大小",SizeDisplay(app));AddDetailRow(table,"安装位置",GetInstallFolder(app)??app.Location);AddDetailRow(table,"卸载命令",app.Command);AddDetailRow(table,"图标路径",app.DisplayIcon);AddDetailRow(table,"已记录残留",app.Residues.Count+" 项");
            var close=new Button{Text="关闭",Dock=DockStyle.Bottom,Height=38,FlatStyle=FlatStyle.Flat};close.Click+=(s,ev)=>dialog.Close();dialog.Controls.Add(table);dialog.Controls.Add(close);dialog.Controls.Add(heading);ApplyThemeToControls(dialog);dialog.Shown+=delegate{NativeTheme.SetForm(dialog,true,surfaceColor,textColor,borderColor);};dialog.ShowDialog(this);
        }
        void AddDetailRow(TableLayoutPanel table,string name,string value)
        {
            int row=table.RowCount++;table.RowStyles.Add(new RowStyle(SizeType.Percent,12.5f));var key=new Label{Text=name,Dock=DockStyle.Fill,TextAlign=ContentAlignment.MiddleLeft,ForeColor=mutedColor,Padding=new Padding(0,0,8,0)};var val=new Label{Text=String.IsNullOrWhiteSpace(value)?"未提供":value,Dock=DockStyle.Fill,TextAlign=ContentAlignment.MiddleLeft,ForeColor=textColor,AutoEllipsis=true};tips.SetToolTip(val,val.Text);table.Controls.Add(key,0,row);table.Controls.Add(val,1,row);
        }
        string GetInstallFolder(AppInfo app)
        {
            string path=(app.Location??"").Trim().Trim('"');
            if(File.Exists(path))return Path.GetDirectoryName(path);
            if(Directory.Exists(path))return path;
            path=GetIconPath(app);
            if(!String.IsNullOrEmpty(path)&&File.Exists(path))return Path.GetDirectoryName(path);
            return null;
        }
        void OpenInstallLocation(object sender, EventArgs e)
        {
            if(current==null)return;
            string folder=GetInstallFolder(current);
            if(String.IsNullOrEmpty(folder)||!Directory.Exists(folder)){MessageBox.Show("没有找到该软件的安装目录。","安装位置不可用",MessageBoxButtons.OK,MessageBoxIcon.Information);return;}
            try{Process.Start(new ProcessStartInfo{FileName="explorer.exe",Arguments="\""+folder+"\"",UseShellExecute=true});}catch(Exception ex){MessageBox.Show("无法打开安装位置："+ex.Message,"打开失败",MessageBoxButtons.OK,MessageBoxIcon.Error);}
        }
        List<string> SnapshotInstallFiles(AppInfo app)
        {
            var files=new List<string>();var roots=new[]{app.Location,Path.GetDirectoryName(GetCommandExecutable(app.Command)??"")};
            foreach(string root in roots.Where(x=>!String.IsNullOrWhiteSpace(x)&&Directory.Exists(x)).Distinct(StringComparer.OrdinalIgnoreCase))
            {
                var pending=new Stack<string>();pending.Push(root);
                while(pending.Count>0){string dir=pending.Pop();try{files.AddRange(Directory.EnumerateFiles(dir));}catch{}try{foreach(string sub in Directory.EnumerateDirectories(dir))try{if((File.GetAttributes(sub)&FileAttributes.ReparsePoint)==0)pending.Push(sub);}catch{}}catch{}}
            }
            return files.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        }
        int RecordExternalUninstallChanges(AppInfo app,List<string> before)
        {
            int removed=0;foreach(string path in before??new List<string>())if(!File.Exists(path)){RecordDeleteHistory(app.Name,path,"由卸载程序删除");removed++;}return removed;
        }
        void Uninstall(object sender, EventArgs e)
        {
            if(installedDataScanRunning)return;
            if(current==null||MessageBox.Show("将启动“"+current.Name+"”登记的卸载程序。继续吗？","确认卸载",MessageBoxButtons.YesNo,MessageBoxIcon.Question)!=DialogResult.Yes)return;
            AppInfo uninstalling=current;ShowLoading("正在记录软件安装文件，以便显示卸载删除记录…");
            Task.Run(()=>SnapshotInstallFiles(uninstalling)).ContinueWith(task=>{try{BeginInvoke((Action)delegate{HideLoading();if(task.Status!=TaskStatus.RanToCompletion){MessageBox.Show("无法记录软件文件清单，未启动卸载程序。","卸载准备失败",MessageBoxButtons.OK,MessageBoxIcon.Error);return;}LaunchUninstaller(uninstalling,task.Result);});}catch{HideLoading();}});
        }
        void LaunchUninstaller(AppInfo uninstalling,List<string> filesBefore)
        {
            try
            {
                string cmd=Environment.ExpandEnvironmentVariables(uninstalling.Command.Trim());string exe,args;
                if(cmd.StartsWith("\"")){int i=cmd.IndexOf('"',1);if(i<0)throw new Exception("卸载命令引号不完整");exe=cmd.Substring(1,i-1);args=cmd.Substring(i+1).Trim();}
                else{int i=cmd.IndexOf(' ');exe=i<0?cmd:cmd.Substring(0,i);args=i<0?"":cmd.Substring(i+1).Trim();}
                Process process=Process.Start(new ProcessStartInfo{FileName=exe,Arguments=args,UseShellExecute=true,WorkingDirectory=Path.GetDirectoryName(exe)??Environment.CurrentDirectory});
                MessageBox.Show("卸载程序已启动。关闭卸载程序后会快速核验状态，并把安装目录中消失的文件记入删除记录。需要查找残留时请点击扫描。");
                if(process==null)Task.Run(()=>{System.Threading.Thread.Sleep(1200);BeginInvoke((Action)delegate{QuickCheckUninstall(uninstalling,null,filesBefore);});});
                else Task.Run(()=>{int? exitCode=null;try{process.WaitForExit();exitCode=process.ExitCode;}catch{}try{BeginInvoke((Action)delegate{QuickCheckUninstall(uninstalling,exitCode,filesBefore);});}catch{}});
            }
            catch(Exception ex){MessageBox.Show("启动失败："+ex.Message,"错误",MessageBoxButtons.OK,MessageBoxIcon.Error);}
        }
        void QuickCheckUninstall(AppInfo app,int? exitCode,List<string> filesBefore)
        {
            ShowLoading("正在快速核验卸载状态…");
            Task.Run(()=>{int removedFiles=RecordExternalUninstallChanges(app,filesBefore);UpdateLoadingProgress(250,"检查程序文件和安装目录…");bool installedFiles=HasInstallEvidence(app);UpdateLoadingProgress(700,"检查卸载注册信息…");bool registration=IsUninstallRegistrationPresent(app);UpdateLoadingProgress(1000,"卸载状态核验完成");return new Tuple<bool,bool,int>(installedFiles,registration,removedFiles);}).ContinueWith(task=>{try{BeginInvoke((Action)delegate{HideLoading();if(task.Status!=TaskStatus.RanToCompletion){MessageBox.Show("卸载程序已退出，但快速核验失败。请手动确认卸载状态后，再检查或清理残留。","卸载状态未知",MessageBoxButtons.OK,MessageBoxIcon.Warning);return;}bool hasFiles=task.Result.Item1,hasRegistration=task.Result.Item2;int removedFiles=task.Result.Item3;if(hasFiles||hasRegistration){app.IsInstalled=true;ShowApps();string remaining=hasFiles?"仍发现程序文件或安装目录":"仍发现卸载注册信息";string code=exitCode.HasValue?"卸载程序退出码："+exitCode.Value+"。\r\n":"";MessageBox.Show("卸载未能确认成功："+remaining+"。\r\n"+code+"为避免误删仍在使用的文件，暂未自动清理残留。可以重新运行该软件的卸载程序，或确认软件已停用后再手动检查。","卸载检查未通过",MessageBoxButtons.OK,MessageBoxIcon.Warning);return;}MarkExplicitlyUninstalled(app);app.IsInstalled=false;ShowApps();string result="快速检查通过：未发现程序文件、安装目录或卸载注册信息。"+(exitCode.HasValue?"\r\n卸载程序退出码："+exitCode.Value+"。":"");MessageBox.Show(result+"\r\n卸载程序删除的文件："+removedFiles+" 项已记录；需要查找残留时请点击扫描。","卸载检查通过",MessageBoxButtons.OK,MessageBoxIcon.Information);});}catch{HideLoading();}});
        }
        bool IsUninstallRegistrationPresent(AppInfo app)
        {
            const string rootPath=@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
            foreach(RegistryHive hive in new[]{RegistryHive.LocalMachine,RegistryHive.CurrentUser})foreach(RegistryView view in new[]{RegistryView.Registry64,RegistryView.Registry32})try{using(var root=RegistryKey.OpenBaseKey(hive,view).OpenSubKey(rootPath)){if(root==null)continue;foreach(string child in root.GetSubKeyNames())try{using(var key=root.OpenSubKey(child)){if(key==null)continue;string name=Convert.ToString(key.GetValue("DisplayName"));if(Norm(name)!=Norm(app.Name))continue;string version=Convert.ToString(key.GetValue("DisplayVersion"));string publisher=Convert.ToString(key.GetValue("Publisher"));if(!String.IsNullOrWhiteSpace(app.Version)&&!String.IsNullOrWhiteSpace(version)&&!String.Equals(app.Version,version,StringComparison.OrdinalIgnoreCase))continue;if(!String.IsNullOrWhiteSpace(app.Publisher)&&!String.IsNullOrWhiteSpace(publisher)&&!String.Equals(app.Publisher,publisher,StringComparison.OrdinalIgnoreCase))continue;return true;}}catch{}}}catch{}return false;
        }
        void ScanAfterUninstall(AppInfo app)
        {
            if(installedDataScanRunning)return;
            ShowLoading("正在查找“"+app.Name+"”的常见残留文件和注册表项…");
            Task.Run(()=>{var items=ScanAppResidues(app,false,(path,done,total)=>UpdateLoadingProgress(total==0?0:(int)(done*650L/total),"正在扫描目录："+path));var report=BuildResidueReport(items,(path,done,total)=>UpdateLoadingProgress(650+(total==0?350:(int)(done*350L/total)),"正在统计文件："+path));UpdateLoadingProgress(1000,"残留扫描完成");return new Tuple<List<Candidate>,ResidueReport>(items,report);}).ContinueWith(task=>{try{BeginInvoke((Action)delegate{HideLoading();if(task.Status!=TaskStatus.RanToCompletion){MessageBox.Show("残留扫描失败，请使用右键菜单重新检查。","扫描失败",MessageBoxButtons.OK,MessageBoxIcon.Error);return;}app.IsInstalled=false;app.Residues=task.Result.Item1;ResidueReport report=task.Result.Item2;app.SizeBytes=report.TotalSizeBytes;app.HasKnownSize=report.Complete;app.SizeCalculationComplete=true;app.DataItems=report.Entries.Select(e=>CreateDataItem(e)).ToList();AppInfo existing=inventory.Find(a=>Norm(a.Name)==Norm(app.Name));if(existing==null)inventory.Add(app);else{existing.IsInstalled=false;existing.Residues=app.Residues;existing.DataItems=app.DataItems;existing.SizeBytes=app.SizeBytes;existing.HasKnownSize=app.HasKnownSize;existing.SizeCalculationComplete=true;}ShowApps();if(app.Residues.Count==0){MessageBox.Show("未在常见位置发现该软件的残留文件或注册表项。","扫描完成",MessageBoxButtons.OK,MessageBoxIcon.Information);return;}string prompt="找到“"+app.Name+"”的常见残留：\r\n"+report.FileCount+" 个文件、"+report.FolderCount+" 个文件夹、"+report.RegistryCount+" 个注册表项。\r\n\r\n是否删除这些残留？文件和文件夹将永久删除，注册表项会先备份。";if(MessageBox.Show(prompt,"删除卸载残留",MessageBoxButtons.YesNo,MessageBoxIcon.Warning)!=DialogResult.Yes)return;DeleteResiduesWithLoading(app,app.Residues,false);});}catch{HideLoading();}});
        }
        void DeleteResiduesWithLoading(AppInfo app,List<Candidate> items,bool globalRescan)
        {
            if(installedDataScanRunning)return;
            ShowLoading("正在删除残留，窗口会显示当前处理位置…");
            Task.Run(()=>CleanAndRescan(app,items,globalRescan,(path,done,total)=>UpdateLoadingProgress(total==0?0:(int)(done*1000L/total),"正在处理残留及复查："+path))).ContinueWith(task=>{try{BeginInvoke((Action)delegate{HideLoading();if(task.Status!=TaskStatus.RanToCompletion){MessageBox.Show("删除过程未完成，请重新扫描核对。","删除失败",MessageBoxButtons.OK,MessageBoxIcon.Error);return;}CleanupReport result=task.Result;app.Residues=result.Remaining;ResidueReport left=result.RemainingSummary??new ResidueReport();app.SizeBytes=left.TotalSizeBytes;app.HasKnownSize=left.Complete;app.SizeCalculationComplete=true;app.DataItems=left.Entries.Select(e=>CreateDataItem(e)).ToList();if(result.Remaining.Count==0&&!app.IsInstalled){inventory.Remove(app);archivedDataApps.RemoveAll(a=>AppKey(a)==AppKey(app));}ShowApps();string text="本次已记录删除位置："+result.DeletedItems.Count+" 项。\r\n删除后复查："+left.FileCount+" 个文件、"+left.FolderCount+" 个文件夹、"+left.RegistryCount+" 个注册表项仍存在。";if(result.Errors.Length>0)text+="\r\n\r\n未能处理：\r\n"+result.Errors;MessageBox.Show(text,"残留清理结果",MessageBoxButtons.OK,result.Remaining.Count==0&&result.Errors.Length==0?MessageBoxIcon.Information:MessageBoxIcon.Warning);});}catch{HideLoading();}});
        }
        void ValidateDataCache(bool silent=false)
        {
            if(dataCacheValidationRunning)return;
            if(!dataCacheLoaded){dataCacheLoaded=true;fullDataScanRequired=true;dataCacheDirty=true;}
            if(fullDataScanRequired){dataCacheValidationComplete=true;StartInstalledDataScan(silent);return;}
            dataCacheValidationRunning=true;if(!silent){dataTree.Enabled=false;ShowLoading("正在检查已保存的数据缓存…");}
            int generation=dataChangeGeneration;var snapshots=inventory.SelectMany(app=>app.DataItems.Select(item=>new Tuple<string,DataItem,string>(AppKey(app),item,item.Fingerprint))).ToList();var directoryRoots=new Dictionary<string,List<string>>(StringComparer.OrdinalIgnoreCase);foreach(var group in snapshots.Where(x=>x.Item2.RemovalCandidate!=null&&!x.Item2.RemovalCandidate.Registry&&!x.Item2.RemovalCandidate.IsFile).GroupBy(x=>x.Item1,StringComparer.OrdinalIgnoreCase)){var dirs=new HashSet<string>(group.Select(x=>x.Item2.Path.TrimEnd(Path.DirectorySeparatorChar,Path.AltDirectorySeparatorChar)),StringComparer.OrdinalIgnoreCase);var roots=new List<string>();foreach(string dir in dirs){string parent=Path.GetDirectoryName(dir);if(String.IsNullOrEmpty(parent)||!dirs.Contains(parent.TrimEnd(Path.DirectorySeparatorChar,Path.AltDirectorySeparatorChar)))roots.Add(dir);}directoryRoots[group.Key]=roots;}var snapshotsToCheck=snapshots.Where(row=>{Candidate c=row.Item2.RemovalCandidate;if(c==null||c.Registry||!c.IsFile)return true;List<string> roots;if(!directoryRoots.TryGetValue(row.Item1,out roots))return true;return !roots.Any(root=>IsPathWithin(row.Item2.Path,root));}).ToList();string priorRegistrySignature=lastRegistrySignature;
            Task.Run(()=>{var changed=new HashSet<string>(StringComparer.OrdinalIgnoreCase);var upgraded=new Dictionary<DataItem,string>();for(int i=0;i<snapshotsToCheck.Count;i++){if(!silent&&i%25==0)UpdateLoadingProgress(snapshotsToCheck.Count==0?700:(int)(i*700L/snapshotsToCheck.Count),"正在校验目录摘要："+(i+1)+" / "+snapshotsToCheck.Count);var row=snapshotsToCheck[i];string actual=GetDataItemFingerprint(row.Item2);if(!String.Equals(actual,"error")){if(!CacheFingerprintMatches(row.Item3,actual))changed.Add(row.Item1);else if(!String.Equals(row.Item3,actual,StringComparison.Ordinal)&&row.Item2.RemovalCandidate!=null&&!row.Item2.RemovalCandidate.Registry&&!row.Item2.RemovalCandidate.IsFile)upgraded[row.Item2]=actual;}}if(!silent)UpdateLoadingProgress(850,"正在检查软件安装清单…");string registrySignature=ReadRegistrySignature();if(!silent)UpdateLoadingProgress(1000,"缓存检查完成");return Tuple.Create(changed,registrySignature,upgraded);}).ContinueWith(task=>{try{BeginInvoke((Action)delegate{dataCacheValidationRunning=false;if(task.Status!=TaskStatus.RanToCompletion){dataCacheValidationComplete=true;dataCacheDirty=true;fullDataScanRequired=true;installedDataScanComplete=false;StartInstalledDataScan(silent);return;}foreach(string key in task.Result.Item1)changedDataAppKeys.Add(key);if(!String.Equals(task.Result.Item2,priorRegistrySignature,StringComparison.OrdinalIgnoreCase)){lastRegistrySignature=task.Result.Item2;if(!String.Equals(task.Result.Item2,BuildInventorySignature(),StringComparison.OrdinalIgnoreCase)){dataCacheDirty=true;dataCacheValidationComplete=false;if(!silent)HideLoading();LoadApps();return;}}if(generation!=dataChangeGeneration)dataCacheDirty=true;if(task.Result.Item1.Count>0){dataCacheDirty=true;dataChangeGeneration++;}else if(!dataCacheDirty&&generation==dataChangeGeneration&&task.Result.Item3.Count>0){foreach(var pair in task.Result.Item3)pair.Key.Fingerprint=pair.Value;SaveDataCache();}dataCacheValidationComplete=true;if(dataCacheDirty||!installedDataScanComplete){StartInstalledDataScan(silent);return;}dataTree.Enabled=true;if(!silent)HideLoading();RenderDataTree();UpdateCountLabel();});}catch{dataCacheValidationRunning=false;}});
        }        static bool CacheFingerprintMatches(string cached,string actual){if(String.Equals(cached,actual,StringComparison.Ordinal))return true;if(cached!=null&&actual!=null&&cached.StartsWith("D|",StringComparison.Ordinal)&&actual.StartsWith("D|",StringComparison.Ordinal)){string[] oldParts=cached.Split('|'),newParts=actual.Split('|');if(oldParts.Length>=2&&newParts.Length>=2&&String.Equals(oldParts[1],newParts[1],StringComparison.Ordinal))return true;}return false;}
        void RefreshDataFingerprints(Action<int,int> progress=null){var items=inventory.Concat(archivedDataApps).SelectMany(a=>a.DataItems).ToList();int completed=0;Parallel.ForEach(items,new ParallelOptions{MaxDegreeOfParallelism=Math.Max(1,Math.Min(2,Environment.ProcessorCount))},item=>{item.Fingerprint=GetDataItemFingerprint(item);int done=Interlocked.Increment(ref completed);if(progress!=null&&(done%25==0||done==items.Count))progress(done,items.Count);});}
        AppInfo CloneForScan(AppInfo app)
        {
            return new AppInfo{Name=app.Name,Version=app.Version,Publisher=app.Publisher,Location=app.Location,Command=app.Command,DisplayIcon=app.DisplayIcon,IconKey=app.IconKey,Type=app.Type,IsInstalled=app.IsInstalled,HasKnownSize=app.HasKnownSize,SizeCalculationComplete=app.SizeCalculationComplete,SizeBytes=app.SizeBytes,Residues=new List<Candidate>(app.Residues),DataItems=app.DataItems.Select(x=>new DataItem{Kind=x.Kind,Path=x.Path,Fingerprint=x.Fingerprint,Size=x.Size,RemovalCandidate=x.RemovalCandidate}).ToList()};
        }
        void StartInstalledDataScan(bool silent=false)
        {
            if(installedDataScanRunning||appsLoading)return;bool full=fullDataScanRequired||!dataCacheLoaded;int scanGeneration=dataChangeGeneration;var scanInventory=inventory.Select(CloneForScan).ToList();List<AppInfo> all=scanInventory.Where(a=>a.IsInstalled||a.Residues.Count>0).ToList();List<AppInfo> apps=full?all:all.Where(a=>changedDataAppKeys.Contains(AppKey(a))).ToList();pendingCacheBaseline.Clear();foreach(AppInfo app in inventory.Concat(archivedDataApps).GroupBy(AppKey,StringComparer.OrdinalIgnoreCase).Select(g=>g.First()))pendingCacheBaseline[AppKey(app)]=CacheAppSignature(app);pendingCacheFullRewrite=!File.Exists(dataCachePath);
            installedDataScanRunning=true;dataTree.Enabled=true;if(!silent)ShowLoading(full?"正在扫描软件数据…":"正在增量扫描有变化的软件数据…");else countLabel.Text="正在后台静默更新数据缓存…";var cancellation=new CancellationTokenSource();dataScanCancellation=cancellation;
            Task.Run(()=>{if(full)ScanInstalledData(apps,scanInventory,cancellation.Token);else ScanChangedApps(apps,cancellation.Token);return scanInventory;},cancellation.Token).ContinueWith(task=>{try{BeginInvoke((Action)delegate{
                if(task.IsCanceled||task.Status!=TaskStatus.RanToCompletion){FinishInstalledDataScan(cancellation,task.IsCanceled,task.IsCanceled?null:"数据扫描失败，请点击扫描重试。",null,silent);return;}
                inventory.Clear();inventory.AddRange(task.Result);bool current=scanGeneration==dataChangeGeneration;cachedInventorySignature=BuildInventorySignature();
                if(current){dataCacheDirty=false;fullDataScanRequired=false;changedDataAppKeys.Clear();installedDataScanComplete=true;}
                else{dataCacheDirty=true;fullDataScanRequired=false;installedDataScanComplete=false;}
                finalCacheWriteRunning=true;if(!silent)ReplaceLoading("扫描完成，准备写入缓存…");UpdateLoadingProgress(0,"正在准备缓存指纹…");Task.Run(()=>{RefreshDataFingerprints((done,total)=>UpdateLoadingProgress(total==0?600:(int)(done*600L/total),"正在刷新缓存指纹（"+done+" / "+total+"）…"));UpdateLoadingProgress(650,"指纹刷新完成，正在写入缓存…");return SaveDataCache((value,text)=>UpdateLoadingProgress(value,text));}).ContinueWith(save=>{try{BeginInvoke((Action)delegate{FinishInstalledDataScan(cancellation,false,save.Status==TaskStatus.RanToCompletion&&save.Result?null:"缓存写入失败，扫描结果已显示；请点击扫描重试。",save.Status==TaskStatus.RanToCompletion&&save.Result,silent);});}catch{}});
                if(activeTab==2)RenderDataTree();else ShowApps();UpdateCountLabel();
            });}catch{if(dataScanCancellation==cancellation)dataScanCancellation=null;installedDataScanRunning=false;cancellation.Dispose();}});
        }
        void FinishInstalledDataScan(CancellationTokenSource cancellation,bool canceled,string error,bool? cacheSaved,bool silent=false)
        {
            if(dataScanCancellation==cancellation)dataScanCancellation=null;installedDataScanRunning=false;finalCacheWriteRunning=false;dataTree.Enabled=true;if(!silent)HideLoading();cancellation.Dispose();
            if(dataInventoryReloadPending&&!appsLoading){dataInventoryReloadPending=false;LoadApps();return;}
            if(canceled){installedDataScanComplete=false;dataCacheDirty=true;countLabel.Text=silent?"后台扫描已取消；点击扫描可重新开始。":"扫描已取消；已恢复上次缓存，点击扫描可重新开始。";return;}
            if(!String.IsNullOrEmpty(error)){countLabel.Text=error;return;}
            if(cacheSaved==true){dataCacheDirty=false;fullDataScanRequired=false;installedDataScanComplete=true;dataCacheValidationComplete=true;}
            if(cacheSaved==false){dataCacheDirty=true;installedDataScanComplete=false;dataCacheValidationComplete=false;if(dataRescanTimer!=null){dataRescanTimer.Stop();dataRescanTimer.Start();}}
            if(activeTab==2)RenderDataTree();else ShowApps();UpdateCountLabel();
        }
        void ScanChangedApps(List<AppInfo> apps,CancellationToken cancellationToken)
        {
            int index=0;foreach(AppInfo app in apps){cancellationToken.ThrowIfCancellationRequested();List<Candidate> candidates=ScanAppResidues(app,false,(path,done,total)=>{if(done%20==0)UpdateLoadingProgress(Math.Min(850,index*850/Math.Max(1,apps.Count)+Math.Min(80,total==0?0:done*80/total)),"正在检查变更软件："+app.Name+"  "+path);},cancellationToken);ResidueReport report=BuildResidueReport(candidates,(path,done,total)=>{if(done%20==0)UpdateLoadingProgress(850+index*150/Math.Max(1,apps.Count),"正在更新变更数据："+path);},cancellationToken);app.Residues=candidates;app.DataItems=report.Entries.Select(CreateDataItem).ToList();index++;}
            UpdateLoadingProgress(1000,"变更数据扫描完成");
        }        static AppInfo MatchDataOwner(string value,Dictionary<string,AppInfo> exactOwners,Regex partialOwnerMatcher){string n=Norm(value);AppInfo match;if(exactOwners.TryGetValue(n,out match))return match;if(partialOwnerMatcher==null)return null;Match found=partialOwnerMatcher.Match(n);return found.Success&&exactOwners.TryGetValue(found.Value,out match)?match:null;}
        void ScanInstalledData(List<AppInfo> apps,List<AppInfo> scanInventory,CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();var names=apps.Select(a=>new KeyValuePair<AppInfo,string>(a,Norm(a.Name))).Where(x=>x.Value.Length>=4).OrderByDescending(x=>x.Value.Length).ToList();var exactOwners=names.GroupBy(x=>x.Value,StringComparer.OrdinalIgnoreCase).ToDictionary(g=>g.Key,g=>g.First().Key,StringComparer.OrdinalIgnoreCase);string pattern=String.Join("|",names.Where(x=>x.Value.Length>=8).Select(x=>Regex.Escape(x.Value)).Distinct(StringComparer.OrdinalIgnoreCase).ToArray());Regex partialMatcher=pattern.Length==0?null:new Regex(pattern,RegexOptions.Compiled|RegexOptions.IgnoreCase|RegexOptions.CultureInvariant);var found=apps.ToDictionary(a=>a,a=>new List<Candidate>());
            string[] roots={Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),Environment.GetFolderPath(Environment.SpecialFolder.StartMenu),Environment.GetFolderPath(Environment.SpecialFolder.CommonStartMenu),Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory)};int scanned=0;
            foreach(string root in roots.Where(x=>!String.IsNullOrWhiteSpace(x)&&Directory.Exists(x)).Distinct(StringComparer.OrdinalIgnoreCase))
            {
                cancellationToken.ThrowIfCancellationRequested();bool searchSecondLevel=root.Equals(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),StringComparison.OrdinalIgnoreCase)||root.Equals(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),StringComparison.OrdinalIgnoreCase)||root.Equals(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),StringComparison.OrdinalIgnoreCase)||root.Equals(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),StringComparison.OrdinalIgnoreCase)||root.Equals(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),StringComparison.OrdinalIgnoreCase);
                try{foreach(string file in Directory.EnumerateFiles(root)){cancellationToken.ThrowIfCancellationRequested();AppInfo owner=MatchDataOwner(Path.GetFileNameWithoutExtension(file),exactOwners,partialMatcher);if(owner!=null)AddLooseFileCandidate(found[owner],file);}foreach(string first in Directory.EnumerateDirectories(root)){cancellationToken.ThrowIfCancellationRequested();scanned++;AppInfo owner=MatchDataOwner(Path.GetFileName(first),exactOwners,partialMatcher);if(owner!=null){AddFolderCandidate(found[owner],first);continue;}if(!searchSecondLevel)continue;try{foreach(string second in Directory.EnumerateDirectories(first)){cancellationToken.ThrowIfCancellationRequested();scanned++;owner=MatchDataOwner(Path.GetFileName(second),exactOwners,partialMatcher);if(owner!=null)AddFolderCandidate(found[owner],second);}}catch(OperationCanceledException){throw;}catch{}}}catch(OperationCanceledException){throw;}catch{}UpdateLoadingProgress(Math.Min(400,scanned/2),"正在快速定位软件数据目录（已检查 "+scanned+" 个目录）");
            }
            foreach(AppInfo app in apps)
            {
                cancellationToken.ThrowIfCancellationRequested();string exe=GetCommandExecutable(app.Command);string[] known={app.Location,!String.IsNullOrWhiteSpace(exe)&&!IsWindowsUtility(Path.GetFileNameWithoutExtension(exe))?Path.GetDirectoryName(exe):null};foreach(string root in known)if(IsSpecificScanRoot(root,roots)){ScanProgress state=FindMatchingFolders(found[app],root,Norm(app.Name),false,(path,done,total)=>{if(done%20==0)UpdateLoadingProgress(Math.Min(650,400+done),"正在检查已安装目录："+path);},cancellationToken);scanned+=state.Scanned;}
            }
            ScanRegistryCandidatesForApps(apps,found,cancellationToken);
            int index=0;foreach(AppInfo app in apps){cancellationToken.ThrowIfCancellationRequested();List<Candidate> candidates=found[app];ResidueReport report=BuildResidueReport(candidates,(path,done,total)=>{if(done%20==0)UpdateLoadingProgress(650+(index*350/Math.Max(1,apps.Count)),"正在枚举数据文件："+path);},cancellationToken);app.Residues=candidates;app.DataItems=report.Entries.Select(e=>CreateDataItem(e)).ToList();index++;UpdateLoadingProgress(650+index*350/Math.Max(1,apps.Count),"正在整理软件数据："+app.Name);}
            cancellationToken.ThrowIfCancellationRequested();DiscoverOrphanResidues(scanInventory,cancellationToken);
            var orphanApps=scanInventory.Where(a=>!a.IsInstalled&&a.Residues.Count>0).ToList();
            int orphanIndex=0;
            foreach(AppInfo app in orphanApps)
            {
                ResidueReport report=BuildResidueReport(app.Residues,(path,done,total)=>{if(done%20==0)UpdateLoadingProgress(900+(orphanApps.Count==0?0:orphanIndex*100/orphanApps.Count),"正在整理卸载残留："+path);},cancellationToken);
                app.DataItems=report.Entries.Select(e=>CreateDataItem(e)).ToList();
                orphanIndex++;
            }
            UpdateLoadingProgress(1000,"已完成数据扫描");
        }
        static string Norm(string s){return Regex.Replace((s??"").ToLowerInvariant(),"[^a-z0-9\u4e00-\u9fff]","");}
        bool HasInstallEvidence(AppInfo app)
        {
            if(!String.IsNullOrWhiteSpace(app.Location)&&HasApplicationFiles(app.Location))return true;
            string exe=GetCommandExecutable(app.Command);if(!String.IsNullOrEmpty(exe)&&File.Exists(exe)&&!IsWindowsUtility(Path.GetFileNameWithoutExtension(exe))){if(!IsUninstaller(Path.GetFileNameWithoutExtension(exe)))return true;string parent=Path.GetDirectoryName(exe);if(!String.IsNullOrEmpty(parent)&&HasApplicationFiles(parent))return true;}
            return IsMsiProductInstalled(app.Command);
        }
        [DllImport("msi.dll",CharSet=CharSet.Unicode,EntryPoint="MsiQueryProductStateW")]
        static extern int MsiQueryProductState(string productCode);
        static bool IsMsiProductInstalled(string command)
        {
            Match match=Regex.Match(command??"",@"\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}");if(!match.Success)return false;try{int state=MsiQueryProductState(match.Value);return state==3||state==5;}catch{return false;}
        }
        static bool HasApplicationFiles(string location)
        {
            if(File.Exists(location))return true;if(!Directory.Exists(location))return false;
            var pending=new Stack<KeyValuePair<string,int>>();pending.Push(new KeyValuePair<string,int>(location,0));try{while(pending.Count>0){var item=pending.Pop();foreach(string file in Directory.GetFiles(item.Key,"*.exe"))if(!IsUninstaller(Path.GetFileNameWithoutExtension(file)))return true;if(item.Value>=3)continue;foreach(string sub in Directory.GetDirectories(item.Key))try{if((File.GetAttributes(sub)&FileAttributes.ReparsePoint)==0)pending.Push(new KeyValuePair<string,int>(sub,item.Value+1));}catch{}}return false;}catch(UnauthorizedAccessException){return true;}catch{return false;}
        }
        static bool IsUninstaller(string name){string n=(name??"").ToLowerInvariant();return n.Contains("uninstall")||n.StartsWith("unins")||n=="setup"||n=="maintenancetool";}
        static bool IsWindowsUtility(string name){string n=(name??"").ToLowerInvariant();return n=="msiexec"||n=="rundll32"||n=="regsvr32"||n=="cmd"||n=="powershell"||n=="wscript"||n=="cscript";}
        static string GetCommandExecutable(string command)
        {
            if(String.IsNullOrWhiteSpace(command))return null;string value=Environment.ExpandEnvironmentVariables(command.Trim());if(value.StartsWith("\"")){int end=value.IndexOf('"',1);if(end>1)return value.Substring(1,end-1);}int space=value.IndexOf(' ');return space<0?value:value.Substring(0,space);
        }
        List<Candidate> ScanAppResidues(AppInfo app,bool global=false,Action<string,int,int> progress=null,CancellationToken cancellationToken=default(CancellationToken),bool includeRegistry=true)
        {
            var found=new List<Candidate>();string n=Norm(app.Name);if(n.Length<4)return found;
            string uninstaller=GetCommandExecutable(app.Command);string uninstallerDir=!String.IsNullOrWhiteSpace(uninstaller)&&!IsWindowsUtility(Path.GetFileNameWithoutExtension(uninstaller))?Path.GetDirectoryName(uninstaller):null;var uniqueRoots=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if(global){var drives=new List<string>();foreach(DriveInfo drive in DriveInfo.GetDrives())try{if(drive.DriveType==DriveType.Fixed&&drive.IsReady&&uniqueRoots.Add(drive.RootDirectory.FullName))drives.Add(drive.RootDirectory.FullName);}catch{}object gate=new object();var states=new Dictionary<string,ScanProgress>(StringComparer.OrdinalIgnoreCase);Parallel.ForEach(drives,new ParallelOptions{MaxDegreeOfParallelism=Math.Max(1,Math.Min(2,drives.Count)),CancellationToken=cancellationToken},root=>{var local=new List<Candidate>();ScanProgress state=FindMatchingFolders(local,root,n,true,(path,done,total)=>{int allDone,allTotal;lock(gate){states[root]=new ScanProgress{Scanned=done,Total=total};allDone=states.Values.Sum(x=>x.Scanned);allTotal=states.Values.Sum(x=>x.Total);}if(progress!=null)progress(path,allDone,allTotal);},cancellationToken);lock(gate){states[root]=state;found.AddRange(local);}});}
            else
            {
                string[] bases={Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),Environment.GetFolderPath(Environment.SpecialFolder.StartMenu),Environment.GetFolderPath(Environment.SpecialFolder.CommonStartMenu),Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory)};
                foreach(string known in new[]{app.Location,uninstallerDir})if(IsSpecificScanRoot(known,bases)&&uniqueRoots.Add(known)){}
                foreach(string root in bases.Where(x=>!String.IsNullOrWhiteSpace(x)&&Directory.Exists(x)).Distinct(StringComparer.OrdinalIgnoreCase))
                {
                    cancellationToken.ThrowIfCancellationRequested();try
                    {
                        foreach(string file in Directory.EnumerateFiles(root)){cancellationToken.ThrowIfCancellationRequested();if(IsNameMatch(Path.GetFileNameWithoutExtension(file),n))AddLooseFileCandidate(found,file);}
                        foreach(string first in Directory.EnumerateDirectories(root))
                        {
                            cancellationToken.ThrowIfCancellationRequested();if(IsNameMatch(Path.GetFileName(first),n)){uniqueRoots.Add(first);continue;}
                            if(root.Equals(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),StringComparison.OrdinalIgnoreCase)||root.Equals(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),StringComparison.OrdinalIgnoreCase)||root.Equals(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),StringComparison.OrdinalIgnoreCase))
                                try{foreach(string second in Directory.EnumerateDirectories(first)){cancellationToken.ThrowIfCancellationRequested();if(IsNameMatch(Path.GetFileName(second),n))uniqueRoots.Add(second);}}catch(OperationCanceledException){throw;}catch{}
                        }
                    }catch(OperationCanceledException){throw;}catch{}
                }
                int done=0;foreach(string root in uniqueRoots.ToArray())if(Directory.Exists(root)){cancellationToken.ThrowIfCancellationRequested();ScanProgress state=FindMatchingFolders(found,root,n,false,(path,scanned,total)=>{if(progress!=null)progress(path,done+scanned,total);},cancellationToken);done+=state.Scanned;}
            }
            if(includeRegistry)ReadRegistryCandidates(found,n);
            return found;
        }
        static bool IsNameMatch(string value,string normalizedName){string candidate=Norm(value);return candidate==normalizedName||(normalizedName.Length>=8&&candidate.Contains(normalizedName));}
        static bool IsSpecificScanRoot(string path,string[] commonRoots)
        {
            if(String.IsNullOrWhiteSpace(path)||!Directory.Exists(path))return false;try{if((File.GetAttributes(path)&FileAttributes.ReparsePoint)!=0)return false;}catch{return false;}string full=Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar,Path.AltDirectorySeparatorChar);string drive=Path.GetPathRoot(full).TrimEnd(Path.DirectorySeparatorChar,Path.AltDirectorySeparatorChar);
            if(String.Equals(full,drive,StringComparison.OrdinalIgnoreCase)||commonRoots.Any(r=>!String.IsNullOrWhiteSpace(r)&&String.Equals(full,Path.GetFullPath(r).TrimEnd(Path.DirectorySeparatorChar,Path.AltDirectorySeparatorChar),StringComparison.OrdinalIgnoreCase)))return false;
            return true;
        }
        static ScanProgress FindMatchingFolders(List<Candidate> found,string root,string normalizedName,bool global=false,Action<string,int,int> progress=null,CancellationToken cancellationToken=default(CancellationToken))
        {
            var result=new ScanProgress{Total=1};var pending=new Stack<string>();pending.Push(root);while(pending.Count>0){cancellationToken.ThrowIfCancellationRequested();string current=pending.Pop();result.Scanned++;try{foreach(string file in Directory.EnumerateFiles(current)){cancellationToken.ThrowIfCancellationRequested();string fileName=Norm(Path.GetFileNameWithoutExtension(file));if(fileName==normalizedName||(normalizedName.Length>=8&&fileName.Contains(normalizedName)))AddLooseFileCandidate(found,file);}foreach(string dir in Directory.EnumerateDirectories(current)){cancellationToken.ThrowIfCancellationRequested();string name=Path.GetFileName(dir);bool protectedPath=name.Equals("Windows",StringComparison.OrdinalIgnoreCase)||name.Equals("WindowsApps",StringComparison.OrdinalIgnoreCase)||name.Equals("DriverStore",StringComparison.OrdinalIgnoreCase)||name.Equals("WinSxS",StringComparison.OrdinalIgnoreCase)||name.Equals("$Recycle.Bin",StringComparison.OrdinalIgnoreCase)||name.Equals("System Volume Information",StringComparison.OrdinalIgnoreCase)||name.Equals("Recovery",StringComparison.OrdinalIgnoreCase);if(global&&protectedPath)continue;string normalized=Norm(name);if(normalized==normalizedName||(normalizedName.Length>=8&&normalized.Contains(normalizedName))){try{if((File.GetAttributes(dir)&FileAttributes.ReparsePoint)==0)AddFolderCandidate(found,dir);}catch{}continue;}try{if((File.GetAttributes(dir)&FileAttributes.ReparsePoint)==0){pending.Push(dir);result.Total++;}}catch{}}}catch(OperationCanceledException){throw;}catch{}if(progress!=null)progress(current,result.Scanned,result.Total);}return result;
        }
        static void AddFolderCandidate(List<Candidate> found,string path){foreach(Candidate old in found)if(!old.Registry&&String.Equals(old.Path,path,StringComparison.OrdinalIgnoreCase))return;found.Add(new Candidate{Path=path});}
        static void AddLooseFileCandidate(List<Candidate> found,string path){foreach(Candidate old in found)if(old.IsFile&&String.Equals(old.Path,path,StringComparison.OrdinalIgnoreCase))return;found.Add(new Candidate{Path=path,IsFile=true});}
        void DiscoverOrphanResidues(List<AppInfo> targetInventory,CancellationToken cancellationToken)
        {
            string[] roots={Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData)};
            var folders=new Dictionary<string,string>(StringComparer.OrdinalIgnoreCase);foreach(string root in roots){cancellationToken.ThrowIfCancellationRequested();if(Directory.Exists(root))try{foreach(string dir in Directory.GetDirectories(root)){cancellationToken.ThrowIfCancellationRequested();string name=Path.GetFileName(dir);string key=Norm(name);if(key.Length>=4&&!folders.ContainsKey(key))folders.Add(key,dir);}}catch(OperationCanceledException){throw;}catch{}}
            var skip=new HashSet<string>(StringComparer.OrdinalIgnoreCase){"microsoft","windows","classes","policies","clients","wow6432node","odbc","registeredapplications","google","adobe","mozilla"};
            foreach(RegistryHive hive in new[]{RegistryHive.CurrentUser,RegistryHive.LocalMachine})foreach(RegistryView view in new[]{RegistryView.Registry64,RegistryView.Registry32}){cancellationToken.ThrowIfCancellationRequested();try{using(RegistryKey root=RegistryKey.OpenBaseKey(hive,view).OpenSubKey("SOFTWARE")){if(root==null)continue;foreach(string keyName in root.GetSubKeyNames()){cancellationToken.ThrowIfCancellationRequested();string norm=Norm(keyName);if(norm.Length<4||skip.Contains(norm)||!folders.ContainsKey(norm)||targetInventory.Exists(a=>Norm(a.Name)==norm&&a.IsInstalled))continue;string folder=folders[norm];AppInfo app=targetInventory.Find(a=>Norm(a.Name)==norm);if(app==null){app=new AppInfo{Name=Path.GetFileName(folder),Location=folder,IsInstalled=false};targetInventory.Add(app);}AddFolderCandidate(app.Residues,folder);string sub="SOFTWARE\\"+keyName;string full=hive+"\\"+sub+" ["+view+"]";if(!app.Residues.Exists(c=>c.Registry&&c.Path==full))app.Residues.Add(new Candidate{Registry=true,Hive=hive,View=view,Key=sub,Path=full});}}}catch(OperationCanceledException){throw;}catch{}}
            targetInventory.RemoveAll(a=>!a.IsInstalled&&a.Residues.Count==0);
        }
        void ReadRegistryCandidates(List<Candidate> found,string n)
        {
            foreach (var hive in new[] { RegistryHive.CurrentUser, RegistryHive.LocalMachine })
            foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
            foreach (var rootPath in new[] { "SOFTWARE", @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" })
            {
                try
                {
                    using (var root = RegistryKey.OpenBaseKey(hive, view).OpenSubKey(rootPath))
                    {
                        if (root == null) continue;
                        foreach (var child in root.GetSubKeyNames())
                        {
                            try
                            {
                                using (var key = root.OpenSubKey(child))
                                {
                                    if (key == null) continue;
                                    string display = Convert.ToString(key.GetValue("DisplayName"));
                                    if(rootPath=="SOFTWARE")ScanRegistrySubtree(found,hive,view,key,rootPath+"\\"+child,child,display,n,1);
                                    else AddRegistryCandidate(found,hive,view,rootPath,child,display,n);
                                }
                            }
                            catch { }
                        }
                    }
                }
                catch { }
            }
            foreach(var view in new[]{RegistryView.Registry64,RegistryView.Registry32})try{using(var root=RegistryKey.OpenBaseKey(RegistryHive.LocalMachine,view).OpenSubKey(@"SYSTEM\CurrentControlSet\Services")){if(root==null)continue;foreach(string child in root.GetSubKeyNames())try{using(var key=root.OpenSubKey(child)){if(key==null)continue;string display=Convert.ToString(key.GetValue("DisplayName"));string image=Environment.ExpandEnvironmentVariables(Convert.ToString(key.GetValue("ImagePath"))??"");string imageFile=GetCommandExecutable(image);bool matches=Norm(child)==n||Norm(display)==n||(!String.IsNullOrWhiteSpace(imageFile)&&Norm(Path.GetFileNameWithoutExtension(imageFile))==n);if(matches){AddRegistryCandidate(found,RegistryHive.LocalMachine,view,@"SYSTEM\CurrentControlSet\Services",child,display,n);if(!String.IsNullOrWhiteSpace(imageFile)&&File.Exists(imageFile))AddLooseFileCandidate(found,imageFile);}}}catch{}}}catch{}
        }
        void ScanRegistryCandidatesForApps(List<AppInfo> apps,Dictionary<AppInfo,List<Candidate>> found,CancellationToken cancellationToken)
        {
            var owners=new Dictionary<string,List<AppInfo>>(StringComparer.OrdinalIgnoreCase);
            foreach(AppInfo app in apps){string name=Norm(app.Name);if(name.Length<4)continue;List<AppInfo> matches;if(!owners.TryGetValue(name,out matches))owners[name]=matches=new List<AppInfo>();matches.Add(app);}
            foreach(RegistryHive hive in new[]{RegistryHive.CurrentUser,RegistryHive.LocalMachine})foreach(RegistryView view in new[]{RegistryView.Registry64,RegistryView.Registry32})
            {
                cancellationToken.ThrowIfCancellationRequested();
                try{using(RegistryKey root=RegistryKey.OpenBaseKey(hive,view).OpenSubKey("SOFTWARE")){if(root!=null)foreach(string child in root.GetSubKeyNames()){cancellationToken.ThrowIfCancellationRequested();try{using(RegistryKey key=root.OpenSubKey(child)){if(key!=null)ScanRegistryAppTree(found,owners,hive,view,key,"SOFTWARE\\"+child,child,Convert.ToString(key.GetValue("DisplayName")),1,cancellationToken);}}catch(OperationCanceledException){throw;}catch{}}}}catch(OperationCanceledException){throw;}catch{}
                const string uninstallRoot=@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
                try{using(RegistryKey root=RegistryKey.OpenBaseKey(hive,view).OpenSubKey(uninstallRoot)){if(root!=null)foreach(string child in root.GetSubKeyNames()){cancellationToken.ThrowIfCancellationRequested();try{using(RegistryKey key=root.OpenSubKey(child)){if(key!=null)AddRegistryAppMatch(found,owners,hive,view,uninstallRoot+"\\"+child,child,Convert.ToString(key.GetValue("DisplayName")));}}catch(OperationCanceledException){throw;}catch{}}}}catch(OperationCanceledException){throw;}catch{}
                if(hive==RegistryHive.LocalMachine)try{using(RegistryKey root=RegistryKey.OpenBaseKey(hive,view).OpenSubKey(@"SYSTEM\CurrentControlSet\Services")){if(root!=null)foreach(string child in root.GetSubKeyNames()){cancellationToken.ThrowIfCancellationRequested();try{using(RegistryKey key=root.OpenSubKey(child)){if(key==null)continue;string display=Convert.ToString(key.GetValue("DisplayName"));string image=Environment.ExpandEnvironmentVariables(Convert.ToString(key.GetValue("ImagePath"))??"");string imageFile=GetCommandExecutable(image);string ownerName=owners.ContainsKey(Norm(child))?child:owners.ContainsKey(Norm(display))?display:(!String.IsNullOrWhiteSpace(imageFile)?Path.GetFileNameWithoutExtension(imageFile):"");List<AppInfo> serviceOwners;if(!owners.TryGetValue(Norm(ownerName),out serviceOwners))continue;string servicePath=@"SYSTEM\CurrentControlSet\Services\"+child;string full=hive+"\\"+servicePath+" ["+view+"]";foreach(AppInfo app in serviceOwners)if(!found[app].Any(c=>c.Registry&&String.Equals(c.Path,full,StringComparison.OrdinalIgnoreCase)))found[app].Add(new Candidate{Registry=true,Hive=hive,View=view,Key=servicePath,Path=full});if(!String.IsNullOrWhiteSpace(imageFile)&&File.Exists(imageFile))foreach(AppInfo app in serviceOwners)AddLooseFileCandidate(found[app],imageFile);}}catch(OperationCanceledException){throw;}catch{}}}}catch(OperationCanceledException){throw;}catch{}
            }
        }
        static void ScanRegistryAppTree(Dictionary<AppInfo,List<Candidate>> found,Dictionary<string,List<AppInfo>> owners,RegistryHive hive,RegistryView view,RegistryKey key,string path,string name,string display,int depth,CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();if(AddRegistryAppMatch(found,owners,hive,view,path,name,display))return;
            if(depth>=6||name.Equals("Classes",StringComparison.OrdinalIgnoreCase)||name.Equals("Policies",StringComparison.OrdinalIgnoreCase)||name.Equals("ODBC",StringComparison.OrdinalIgnoreCase)||name.Equals("Wow6432Node",StringComparison.OrdinalIgnoreCase)||name.Equals("RegisteredApplications",StringComparison.OrdinalIgnoreCase))return;
            try{foreach(string child in key.GetSubKeyNames()){cancellationToken.ThrowIfCancellationRequested();try{using(RegistryKey sub=key.OpenSubKey(child)){if(sub!=null)ScanRegistryAppTree(found,owners,hive,view,sub,path+"\\"+child,child,Convert.ToString(sub.GetValue("DisplayName")),depth+1,cancellationToken);}}catch(OperationCanceledException){throw;}catch{}}}catch(OperationCanceledException){throw;}catch{}
        }
        static bool AddRegistryAppMatch(Dictionary<AppInfo,List<Candidate>> found,Dictionary<string,List<AppInfo>> owners,RegistryHive hive,RegistryView view,string path,string name,string display)
        {
            List<AppInfo> matches;bool matched=owners.TryGetValue(Norm(name),out matches)||owners.TryGetValue(Norm(display),out matches);if(!matched)return false;
            string full=hive+"\\"+path+" ["+view+"]";foreach(AppInfo app in matches)if(!found[app].Any(c=>c.Registry&&String.Equals(c.Path,full,StringComparison.OrdinalIgnoreCase)))found[app].Add(new Candidate{Registry=true,Hive=hive,View=view,Key=path,Path=full});return true;
        }
        static void ScanRegistrySubtree(List<Candidate> found,RegistryHive hive,RegistryView view,RegistryKey key,string path,string name,string display,string normalizedName,int depth)
        {
            if(Norm(name)==normalizedName||Norm(display)==normalizedName){string full=hive+"\\"+path+" ["+view+"]";if(!found.Exists(c=>c.Registry&&c.Path==full))found.Add(new Candidate{Registry=true,Hive=hive,View=view,Key=path,Path=full});return;}
            if(depth>=6||name.Equals("Classes",StringComparison.OrdinalIgnoreCase)||name.Equals("Policies",StringComparison.OrdinalIgnoreCase)||name.Equals("ODBC",StringComparison.OrdinalIgnoreCase)||name.Equals("Wow6432Node",StringComparison.OrdinalIgnoreCase)||name.Equals("RegisteredApplications",StringComparison.OrdinalIgnoreCase))return;
            try{foreach(string child in key.GetSubKeyNames())try{using(RegistryKey sub=key.OpenSubKey(child)){if(sub!=null)ScanRegistrySubtree(found,hive,view,sub,path+"\\"+child,child,Convert.ToString(sub.GetValue("DisplayName")),normalizedName,depth+1);}}catch{}}catch{}
        }
        static void AddRegistryCandidate(List<Candidate> found,RegistryHive hive,RegistryView view,string rootPath,string child,string display,string normalizedName)
        {
            if(Norm(child)!=normalizedName&&Norm(display)!=normalizedName)return;string subkey=rootPath+"\\"+child;string full=hive+"\\"+subkey+" ["+view+"]";if(found.Exists(c=>c.Registry&&c.Path==full))return;found.Add(new Candidate{Registry=true,Hive=hive,View=view,Key=subkey,Path=full});
        }
        void ShowResidueDetails(object sender, EventArgs e)
        {
            if(current==null||current.IsInstalled)return;
            AppInfo target=current;var dialog=new Form{Text="koka - 残留明细 - "+target.Name,Width=1000,Height=680,MinimumSize=new Size(760,480),StartPosition=FormStartPosition.CenterParent,Font=Font,Icon=this.Icon};
            var entries=target.DataItems.ToList();if(entries.Count==0)entries=target.Residues.Select(c=>new DataItem{Kind=c.Registry?"注册表项":c.IsFile?"文件":"残留文件夹",Path=c.Path,RemovalCandidate=c}).ToList();
            var summary=new Label{Dock=DockStyle.Top,Height=38,Text="“"+target.Name+"”的残留明细："+entries.Count+" 项；勾选后可批量删除",TextAlign=ContentAlignment.MiddleLeft};
            var list=new ListView{Dock=DockStyle.Fill,View=View.Details,FullRowSelect=true,MultiSelect=true,CheckBoxes=true,HideSelection=false,OwnerDraw=true,GridLines=false,BorderStyle=BorderStyle.None};list.DrawColumnHeader+=DrawListHeader;list.DrawItem+=delegate{};list.DrawSubItem+=DrawListSubItem;list.Columns.Add("类型",130);list.Columns.Add("大小",100);list.Columns.Add("完整路径 / 注册表项",740);ColumnHeader filler=list.Columns.Add(" ",0);list.SizeChanged+=delegate{FitFillerColumn(list,filler);};
            var footer=new Panel{Dock=DockStyle.Bottom,Height=78};var progress=new ProgressBar{Dock=DockStyle.Top,Height=12,Minimum=0,Maximum=1000,Value=0,Visible=false};var buttons=new FlowLayoutPanel{Dock=DockStyle.Bottom,Height=40,FlowDirection=FlowDirection.RightToLeft,WrapContents=false,Padding=new Padding(0,3,0,0)};var close=new Button{Text="关闭",Width=86,Height=32};var remove=new Button{Text="删除选中",Width=112,Height=32};var selectAll=new Button{Text="全选",Width=86,Height=32};close.Click+=(s,ev)=>dialog.Close();selectAll.Click+=(s,ev)=>{bool check=list.Items.Cast<ListViewItem>().Any(item=>!item.Checked);foreach(ListViewItem item in list.Items)item.Checked=check;selectAll.Text=check?"取消全选":"全选";};
            remove.Click+=(s,ev)=>{var selected=list.CheckedItems.Cast<ListViewItem>().Select(item=>item.Tag as DataItem).Where(item=>item!=null&&item.RemovalCandidate!=null).ToList();if(selected.Count==0){MessageBox.Show(dialog,"请先勾选要删除的残留项。","删除残留",MessageBoxButtons.OK,MessageBoxIcon.Information);return;}if(installedDataScanRunning){MessageBox.Show(dialog,"当前正在扫描，请扫描完成后再删除。","删除残留",MessageBoxButtons.OK,MessageBoxIcon.Information);return;}string prompt="即将永久删除所选的 "+selected.Count+" 项残留。注册表项会先导出备份。\r\n\r\n是否继续？";if(MessageBox.Show(dialog,prompt,"确认删除残留",MessageBoxButtons.YesNo,MessageBoxIcon.Warning)!=DialogResult.Yes)return;var candidates=selected.Select(item=>item.RemovalCandidate).GroupBy(c=>c.Registry?"R|"+c.Hive+"|"+c.View+"|"+c.Key:"F|"+c.Path,StringComparer.OrdinalIgnoreCase).Select(g=>g.First()).ToList();var cacheBaseline=inventory.Concat(archivedDataApps).GroupBy(AppKey,StringComparer.OrdinalIgnoreCase).ToDictionary(g=>g.Key,g=>CacheAppSignature(g.First()),StringComparer.OrdinalIgnoreCase);remove.Enabled=false;selectAll.Enabled=false;close.Enabled=false;list.Enabled=false;progress.Visible=true;progress.Value=0;summary.Text="正在删除所选的 "+candidates.Count+" 项，并复查该软件剩余数据…";Task.Run(()=>CleanAndRescan(target,candidates,false,(path,done,total)=>{try{dialog.BeginInvoke((Action)delegate{if(dialog.IsDisposed)return;progress.Value=total==0?0:(int)(done*1000L/total);summary.Text="正在处理："+path;});}catch{}})).ContinueWith(task=>{try{dialog.BeginInvoke((Action)delegate{if(dialog.IsDisposed)return;remove.Enabled=true;selectAll.Enabled=true;close.Enabled=true;list.Enabled=true;if(task.Status!=TaskStatus.RanToCompletion){progress.Visible=false;summary.Text="删除过程未完成，请重新扫描核对。";MessageBox.Show(dialog,"删除过程未完成，请重新扫描核对。","删除失败",MessageBoxButtons.OK,MessageBoxIcon.Error);return;}CleanupReport result=task.Result;pendingCacheBaseline.Clear();foreach(var pair in cacheBaseline)pendingCacheBaseline[pair.Key]=pair.Value;target.Residues=result.Remaining;ResidueReport report=result.RemainingSummary??new ResidueReport();target.DataItems=report.Entries.Select(CreateDataItem).ToList();target.SizeBytes=report.TotalSizeBytes;target.HasKnownSize=report.Complete;target.SizeCalculationComplete=true;if(!target.IsInstalled&&target.DataItems.Count==0){inventory.Remove(target);archivedDataApps.RemoveAll(a=>AppKey(a)==AppKey(target));dialog.Close();}else{entries.Clear();entries.AddRange(target.DataItems);list.BeginUpdate();list.Items.Clear();foreach(DataItem entry in entries){var row=new ListViewItem(entry.Kind??"数据"){Tag=entry};row.SubItems.Add(entry.Size>0?FormatSize(entry.Size):"");row.SubItems.Add(entry.Path??"");list.Items.Add(row);}list.EndUpdate();progress.Value=1000;progress.Visible=false;selectAll.Text="全选";summary.Text="删除复查完成：成功记录 "+result.DeletedItems.Count+" 个位置；仍有 "+entries.Count+" 项残留。";}RenderDataTree();ShowApps();UpdateCountLabel();Task.Run(()=>SaveDataCache());if(!String.IsNullOrEmpty(result.Errors))MessageBox.Show(dialog,"部分所选项目未能处理：\r\n"+result.Errors,"部分删除",MessageBoxButtons.OK,MessageBoxIcon.Warning);});}catch{}});};
            footer.Controls.Add(progress);footer.Controls.Add(buttons);buttons.Controls.Add(close);buttons.Controls.Add(remove);buttons.Controls.Add(selectAll);dialog.Controls.Add(list);dialog.Controls.Add(footer);dialog.Controls.Add(summary);ApplyThemeToControls(dialog);dialog.Shown+=delegate{NativeTheme.SetForm(dialog,darkTheme,surfaceColor,textColor,borderColor);FitFillerColumn(list,filler);};
            list.BeginUpdate();foreach(DataItem entry in entries){if(entry.RemovalCandidate==null)entry.RemovalCandidate=CandidateFromData(entry.Kind,entry.Path);var row=new ListViewItem(entry.Kind??"数据"){Tag=entry};row.SubItems.Add(entry.Size>0?FormatSize(entry.Size):"");row.SubItems.Add(entry.Path??"");list.Items.Add(row);}list.EndUpdate();
            dialog.ShowDialog(this);
        }
        void ShowGlobalScanPreview(object sender,EventArgs e)
        {
            if(current==null)return;AppInfo target=current;
            string warning="将扫描本机所有固定磁盘，查找名称与所选软件匹配的文件和文件夹，可能需要较长时间。相似名称可能属于个人文件或共享组件。\r\n\r\n此页面只查看扫描候选，不会删除文件或注册表项。继续吗？";
            if(MessageBox.Show(warning,"全盘扫描提示",MessageBoxButtons.YesNo,MessageBoxIcon.Warning)!=DialogResult.Yes)return;
            var dialog=new Form{Text="koka - 全盘候选扫描 - "+target.Name,Width=1000,Height=680,MinimumSize=new Size(760,480),StartPosition=FormStartPosition.CenterParent,Font=Font,Icon=this.Icon};
            var summary=new Label{Dock=DockStyle.Top,Height=42,Text="正在扫描本机固定磁盘，请稍候…窗口仍可操作。",TextAlign=ContentAlignment.MiddleLeft};
            var progress=new ProgressBar{Dock=DockStyle.Top,Height=20,Minimum=0,Maximum=1000,Value=0,Style=ProgressBarStyle.Continuous};
            var scannedPaths=new ListBox{Dock=DockStyle.Top,Height=130,HorizontalScrollbar=true};
            var list=new ListView{Dock=DockStyle.Fill,View=View.Details,FullRowSelect=true,OwnerDraw=true,GridLines=false,BorderStyle=BorderStyle.None};list.DrawColumnHeader+=DrawListHeader;list.DrawItem+=delegate{};list.DrawSubItem+=DrawListSubItem;list.Columns.Add("类型",130);list.Columns.Add("大小",100);list.Columns.Add("候选路径",740);ColumnHeader filler=list.Columns.Add(" ",0);list.SizeChanged+=delegate{FitFillerColumn(list,filler);};
            var close=new Button{Text="关闭",Dock=DockStyle.Bottom,Height=36};close.Click+=(s,ev)=>dialog.Close();dialog.Controls.Add(list);dialog.Controls.Add(close);dialog.Controls.Add(scannedPaths);dialog.Controls.Add(progress);dialog.Controls.Add(summary);ApplyThemeToControls(dialog);dialog.Shown+=delegate{NativeTheme.SetForm(dialog,darkTheme,surfaceColor,textColor,borderColor);FitFillerColumn(list,filler);};
            int scannedDirectories=0;
            Task.Run(()=>{var items=ScanAppResidues(target,true,(path,done,total)=>{Interlocked.Exchange(ref scannedDirectories,done);SetProgress(progress,summary,total==0?0:(int)(done*700L/total),"已检查 "+done+" / "+total+" 个目录，当前："+path);if(done%10==0)try{BeginInvoke((Action)delegate{if(dialog.IsDisposed)return;scannedPaths.Items.Add(path);if(scannedPaths.Items.Count>120)scannedPaths.Items.RemoveAt(0);scannedPaths.TopIndex=scannedPaths.Items.Count-1;});}catch{}});var report=BuildResidueReport(items,(path,done,total)=>SetProgress(progress,summary,700+(total==0?300:(int)(done*300L/total)),"统计候选文件："+path));SetProgress(progress,summary,1000,"全盘候选扫描完成");return new KeyValuePair<List<Candidate>,ResidueReport>(items,report);}).ContinueWith(task=>{try{BeginInvoke((Action)delegate{if(dialog.IsDisposed)return;if(task.Status!=TaskStatus.RanToCompletion){summary.Text="扫描失败。";return;}target.Residues=task.Result.Key;ResidueReport report=task.Result.Value;target.DataItems=report.Entries.Select(x=>CreateDataItem(x)).ToList();progress.Value=1000;summary.Text="扫描完成：检查了 "+scannedDirectories+" 个目录，找到 "+report.FileCount+" 个文件、"+report.FolderCount+" 个文件夹、"+report.RegistryCount+" 个注册表项。候选仅供核对，不会自动删除。100%";list.BeginUpdate();foreach(ResidueEntry entry in report.Entries){var row=new ListViewItem(entry.Kind);row.SubItems.Add(entry.Size>0?FormatSize(entry.Size):"");row.SubItems.Add(entry.Path);list.Items.Add(row);}list.EndUpdate();UpdateCountLabel();});}catch{}});
            dialog.Show(this);
        }
        ResidueReport BuildResidueReport(List<Candidate> source,Action<string,int,int> progress=null,CancellationToken cancellationToken=default(CancellationToken))
        {
            var report=new ResidueReport();var seenFiles=new HashSet<string>(StringComparer.OrdinalIgnoreCase);var seenFolders=new HashSet<string>(StringComparer.OrdinalIgnoreCase);int scanned=0,total=source.Count(c=>!c.Registry&&!c.IsFile&&Directory.Exists(c.Path));
            foreach(Candidate c in source)
            {
                if(c.Registry){report.RegistryCount++;report.Entries.Add(new ResidueEntry{Kind="注册表项",Path=c.Path,RemovalCandidate=c});continue;}
                if(c.IsFile){if(File.Exists(c.Path)&&seenFiles.Add(c.Path)){long size=0;try{size=new FileInfo(c.Path).Length;report.TotalSizeBytes+=size;}catch{report.Complete=false;}report.FileCount++;report.Entries.Add(new ResidueEntry{Kind="文件",Path=c.Path,Size=size,RemovalCandidate=c});}continue;}
                if(!Directory.Exists(c.Path)||!seenFolders.Add(c.Path))continue;
                report.FolderCount++;report.Entries.Add(new ResidueEntry{Kind="残留文件夹",Path=c.Path,RemovalCandidate=c});
                var pending=new Stack<string>();pending.Push(c.Path);while(pending.Count>0){cancellationToken.ThrowIfCancellationRequested();string dir=pending.Pop();scanned++;try{foreach(string file in Directory.EnumerateFiles(dir)){cancellationToken.ThrowIfCancellationRequested();if(!seenFiles.Add(file))continue;long size=0;try{size=new FileInfo(file).Length;report.TotalSizeBytes+=size;}catch{report.Complete=false;}report.FileCount++;report.Entries.Add(new ResidueEntry{Kind="文件",Path=file,Size=size,RemovalCandidate=new Candidate{Path=file,IsFile=true}});}}catch(OperationCanceledException){throw;}catch{report.Complete=false;}try{foreach(string sub in Directory.EnumerateDirectories(dir)){cancellationToken.ThrowIfCancellationRequested();if(!seenFolders.Add(sub))continue;report.FolderCount++;report.Entries.Add(new ResidueEntry{Kind="子文件夹",Path=sub,RemovalCandidate=new Candidate{Path=sub}});try{if((File.GetAttributes(sub)&FileAttributes.ReparsePoint)==0){pending.Push(sub);total++;}else report.Complete=false;}catch(OperationCanceledException){throw;}catch{report.Complete=false;}}}catch(OperationCanceledException){throw;}catch{report.Complete=false;}if(progress!=null)progress(dir,scanned,total);}
            }
            return report;
        }
        static DataItem CreateDataItem(ResidueEntry entry){return new DataItem{Kind=entry.Kind,Path=entry.Path,Size=entry.Size,RemovalCandidate=entry.RemovalCandidate??CandidateFromData(entry.Kind,entry.Path)};}
        static Candidate CandidateFromData(string kind,string path)
        {
            var candidate=new Candidate{Path=path};if(String.Equals(kind,"注册表项",StringComparison.OrdinalIgnoreCase)){candidate.Registry=true;try{int slash=path.IndexOf('\\');int bracket=path.LastIndexOf(" [",StringComparison.Ordinal);string hive=slash>0?path.Substring(0,slash):"";string key=slash>0?path.Substring(slash+1,bracket>slash?bracket-slash-1:path.Length-slash-1):"";if(bracket>0){string view=path.Substring(bracket+2).TrimEnd(']');candidate.View=view=="Registry32"?RegistryView.Registry32:RegistryView.Registry64;}candidate.Hive=hive=="CurrentUser"?RegistryHive.CurrentUser:hive=="ClassesRoot"?RegistryHive.ClassesRoot:hive=="Users"?RegistryHive.Users:hive=="CurrentConfig"?RegistryHive.CurrentConfig:RegistryHive.LocalMachine;candidate.Key=key;}catch{}return candidate;}candidate.IsFile=String.Equals(kind,"文件",StringComparison.OrdinalIgnoreCase)||(!String.Equals(kind,"残留文件夹",StringComparison.OrdinalIgnoreCase)&&!String.Equals(kind,"子文件夹",StringComparison.OrdinalIgnoreCase)&&!String.IsNullOrEmpty(Path.GetExtension(path)));return candidate;
        }        void CleanCurrentResidues(object sender, EventArgs e)
        {
            if(current==null||current.IsInstalled)return;ScanAfterUninstall(current);
        }
        void RecordDeleteHistory(string appName,string path,string result)
        {
            try
            {
                lock(deleteHistoryLock)
                {
                    Directory.CreateDirectory(Path.GetDirectoryName(deleteHistoryPath));
                    string line=DateTime.Now.ToString("o")+"\t"+CacheEncode(appName)+"\t"+CacheEncode(path)+"\t"+CacheEncode(result);
                    File.AppendAllText(deleteHistoryPath,line+Environment.NewLine,System.Text.Encoding.UTF8);
                }
            }
            catch{}
        }
        void ShowDeleteHistory(object sender,EventArgs e)
        {
            var dialog=new Form{Text="删除记录",Width=1000,Height=620,MinimumSize=new Size(700,400),StartPosition=FormStartPosition.CenterParent,Font=Font,Icon=this.Icon};
            var list=new ListView{Dock=DockStyle.Fill,View=View.Details,FullRowSelect=true,GridLines=false};
            list.Columns.Add("时间",170);list.Columns.Add("软件",180);list.Columns.Add("结果",100);list.Columns.Add("删除的文件或注册表位置",500);
            try
            {
                if(File.Exists(deleteHistoryPath))
                {
                    string[] lines=File.ReadAllLines(deleteHistoryPath,System.Text.Encoding.UTF8);
                    for(int i=lines.Length-1;i>=0&&list.Items.Count<5000;i--)
                    {
                        string[] parts=lines[i].Split('\t');if(parts.Length<4)continue;
                        try{var row=new ListViewItem(DateTime.Parse(parts[0]).ToString("yyyy-MM-dd HH:mm:ss"));row.SubItems.Add(CacheDecode(parts[1]));row.SubItems.Add(CacheDecode(parts[3]));row.SubItems.Add(CacheDecode(parts[2]));list.Items.Add(row);}catch{}
                    }
                }
            }
            catch{}
            dialog.Controls.Add(list);ApplyThemeToControls(dialog);dialog.Shown+=delegate{NativeTheme.SetForm(dialog,darkTheme,surfaceColor,textColor,borderColor);};dialog.ShowDialog(this);
        }
        List<string> GetCandidateDeletionPaths(Candidate candidate)
        {
            var paths=new List<string>();if(candidate.Registry){paths.Add(candidate.Path);return paths;}
            if(candidate.IsFile){if(File.Exists(candidate.Path))paths.Add(candidate.Path);return paths;}
            if(!Directory.Exists(candidate.Path))return paths;
            paths.Add(candidate.Path);var pending=new Stack<string>();pending.Push(candidate.Path);
            while(pending.Count>0)
            {
                string dir=pending.Pop();
                try{foreach(string file in Directory.EnumerateFiles(dir))paths.Add(file);}catch{}
                try{foreach(string sub in Directory.EnumerateDirectories(dir)){paths.Add(sub);try{if((File.GetAttributes(sub)&FileAttributes.ReparsePoint)==0)pending.Push(sub);}catch{}}}catch{}
            }
            return paths;
        }
        bool CandidateStillExists(Candidate candidate)
        {
            if(candidate.Registry){try{using(var key=RegistryKey.OpenBaseKey(candidate.Hive,candidate.View).OpenSubKey(candidate.Key))return key!=null;}catch{return true;}}
            return candidate.IsFile?File.Exists(candidate.Path):Directory.Exists(candidate.Path);
        }
        CleanupReport CleanAndRescan(AppInfo app,List<Candidate> items,bool globalRescan=false,Action<string,int,int> progress=null)
        {
            var report=new CleanupReport();string backup=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"koka","RegistryBackups",DateTime.Now.ToString("yyyyMMdd-HHmmss"));int processed=0,scale=Math.Max(1,items.Count),progressTotal=scale*3;
            foreach(Candidate c in items)
            {
                processed++;List<string> paths=GetCandidateDeletionPaths(c);
                try
                {
                    if(c.Registry)
                    {
                        Directory.CreateDirectory(backup);string hiveName=c.Hive==RegistryHive.CurrentUser?"HKEY_CURRENT_USER":"HKEY_LOCAL_MACHINE";string regPath=hiveName+"\\"+c.Key;
                        if(c.View==RegistryView.Registry32&&c.Key.StartsWith("SOFTWARE\\",StringComparison.OrdinalIgnoreCase))regPath=hiveName+"\\SOFTWARE\\WOW6432Node\\"+c.Key.Substring(8);
                        string file=Path.Combine(backup,Regex.Replace(c.Hive+"-"+c.Key+"-"+c.View,"[^A-Za-z0-9._-]","_")+".reg");
                        using(var p=Process.Start(new ProcessStartInfo{FileName="reg.exe",Arguments="export \""+regPath+"\" \""+file+"\" /y",UseShellExecute=false,CreateNoWindow=true,RedirectStandardError=true})){p.WaitForExit();if(p.ExitCode!=0||!File.Exists(file))throw new Exception("注册表备份失败："+p.StandardError.ReadToEnd());}
                        using(var baseKey=RegistryKey.OpenBaseKey(c.Hive,c.View))baseKey.DeleteSubKeyTree(c.Key);
                    }
                    else if(c.IsFile){if(File.Exists(c.Path))FileSystem.DeleteFile(c.Path,UIOption.OnlyErrorDialogs,RecycleOption.DeletePermanently);}
                    else if(Directory.Exists(c.Path))FileSystem.DeleteDirectory(c.Path,UIOption.OnlyErrorDialogs,RecycleOption.DeletePermanently);
                    if(paths.Count>0){foreach(string path in paths){report.DeletedItems.Add(path);RecordDeleteHistory(app.Name,path,"成功");}report.Removed++;}
                }
                catch(Exception ex)
                {
                    report.Errors+=c.Path+"\r\n"+ex.Message+"\r\n\r\n";
                    if(c.Registry){if(CandidateStillExists(c)){report.FailedItems.Add(c.Path);RecordDeleteHistory(app.Name,c.Path,"失败："+ex.Message);}else{report.DeletedItems.Add(c.Path);RecordDeleteHistory(app.Name,c.Path,"已删除（部分操作失败）");}}
                    else foreach(string path in paths){if(File.Exists(path)||Directory.Exists(path)){report.FailedItems.Add(path);RecordDeleteHistory(app.Name,path,"失败："+ex.Message);}else{report.DeletedItems.Add(path);RecordDeleteHistory(app.Name,path,"已删除");}}
                }
                if(progress!=null)progress(c.Path,processed,progressTotal);
            }
            report.Remaining=ScanAppResidues(app,globalRescan,(path,done,total)=>{if(progress!=null)progress(path,scale+(total==0?0:(int)(done*scale/Math.Max(1,total))),progressTotal);});
            report.RemainingSummary=BuildResidueReport(report.Remaining,(path,done,total)=>{if(progress!=null)progress(path,scale*2+(total==0?0:(int)(done*scale/Math.Max(1,total))),progressTotal);});return report;
        }
    }
}
