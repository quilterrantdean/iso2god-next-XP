//! One row in the game list: title, details, optional live progress and a remove
//! button. Rows are plain `AdwActionRow`s updated in place.

use std::cell::Cell;
use std::path::PathBuf;

use iso2god_next::SourceKind;
use relm4::adw;
use relm4::adw::prelude::*;
use relm4::gtk::{self, gdk, glib};
use relm4::prelude::*;

use crate::app::{AppModel, AppMsg};
use crate::format;
use crate::model::{EntryState, IsoEntry};

/// Edge length, in pixels, of the game icon shown in front of the title.
const GAME_ICON_SIZE: i32 = 40;

pub struct IsoRow {
    pub row: adw::ActionRow,
    pub path: PathBuf,
    progress: gtk::ProgressBar,
    percent: gtk::Label,
    icon: gtk::Image,
    /// The game's own icon; hidden until there is one.
    game_icon: gtk::Image,
    /// Revision of the icon that `game_icon` shows (`None` before the first
    /// update), so progress updates don't decode the PNG again and again.
    shown_icon: Cell<Option<u32>>,
    choose_icon: gtk::Button,
    revert_icon: gtk::Button,
    remove: gtk::Button,
}

impl IsoRow {
    pub fn new(index: usize, entry: &IsoEntry, sender: &ComponentSender<AppModel>) -> Self {
        let icon = gtk::Image::from_icon_name(icon_for(entry));
        icon.set_valign(gtk::Align::Center);
        icon.add_css_class("dim-label");

        let game_icon = gtk::Image::builder()
            .pixel_size(GAME_ICON_SIZE)
            .valign(gtk::Align::Center)
            .overflow(gtk::Overflow::Hidden)
            .css_classes(["card"])
            .visible(false)
            .build();

        let percent = gtk::Label::builder()
            .width_chars(4)
            .xalign(1.0)
            .valign(gtk::Align::Center)
            .visible(false)
            .css_classes(["dim-label", "numeric"])
            .build();

        let progress = gtk::ProgressBar::builder()
            .width_request(132)
            .valign(gtk::Align::Center)
            .visible(false)
            .build();

        let choose_icon = gtk::Button::builder()
            .icon_name("image-x-generic-symbolic")
            .tooltip_text("Choose a picture to use as the game's icon")
            .valign(gtk::Align::Center)
            .css_classes(["flat"])
            .build();

        let revert_icon = gtk::Button::builder()
            .icon_name("edit-undo-symbolic")
            .tooltip_text("Stop using the chosen picture")
            .valign(gtk::Align::Center)
            .css_classes(["flat"])
            .visible(false)
            .build();

        let remove = gtk::Button::builder()
            .icon_name("window-close-symbolic")
            .tooltip_text("Remove from the list")
            .valign(gtk::Align::Center)
            .css_classes(["flat"])
            .build();

        let row = adw::ActionRow::builder()
            .title(entry.title())
            .subtitle(subtitle(entry))
            .build();

        row.add_prefix(&game_icon);
        row.add_prefix(&icon);
        row.add_suffix(&percent);
        row.add_suffix(&progress);
        row.add_suffix(&choose_icon);
        row.add_suffix(&revert_icon);
        row.add_suffix(&remove);

        let remove_sender = sender.clone();
        remove.connect_clicked(move |_| remove_sender.input(AppMsg::Remove(index)));
        let choose_sender = sender.clone();
        choose_icon.connect_clicked(move |_| choose_sender.input(AppMsg::ChooseIcon(index)));
        let revert_sender = sender.clone();
        revert_icon.connect_clicked(move |_| revert_sender.input(AppMsg::ClearCustomIcon(index)));

        let iso_row = IsoRow {
            row,
            path: entry.path.clone(),
            progress,
            percent,
            icon,
            game_icon,
            shown_icon: Cell::new(None),
            choose_icon,
            revert_icon,
            remove,
        };
        iso_row.update(entry, false);
        iso_row
    }

    pub fn update(&self, entry: &IsoEntry, app_converting: bool) {
        self.row.set_title(&entry.title());
        self.row.set_subtitle(&subtitle(entry));

        let running = match &entry.state {
            EntryState::Converting(progress) => Some(progress.overall_fraction()),
            EntryState::Uploading(progress) => Some(progress.fraction()),
            _ => None,
        };

        self.progress.set_visible(running.is_some());
        self.percent.set_visible(running.is_some());
        if let Some(fraction) = running {
            self.progress.set_fraction(fraction);
            self.percent
                .set_label(&format!("{}%", format::percent(fraction)));
        }

        self.icon.set_icon_name(Some(icon_for(entry)));
        self.icon.set_css_classes(icon_classes(&entry.state));

        if self.shown_icon.get() != Some(entry.icon_revision) {
            self.shown_icon.set(Some(entry.icon_revision));
            let texture = entry.icon().and_then(|png| {
                gdk::Texture::from_bytes(&glib::Bytes::from(png))
                    .inspect_err(|error| eprintln!("iso2god-next-gui: cannot show icon: {error}"))
                    .ok()
            });
            self.game_icon.set_paintable(texture.as_ref());
            self.game_icon.set_visible(texture.is_some());
        }

        let busy = app_converting
            || matches!(
                entry.state,
                EntryState::Queued | EntryState::Converting(_) | EntryState::Uploading(_)
            );
        self.remove.set_sensitive(!busy);
        self.choose_icon
            .set_sensitive(!busy && entry.info.is_some());
        self.revert_icon.set_visible(entry.custom_icon.is_some());
        self.revert_icon.set_sensitive(!busy);

        self.row
            .set_tooltip_text(Some(&entry.path.display().to_string()));
    }
}

fn subtitle(entry: &IsoEntry) -> String {
    match &entry.state {
        EntryState::Inspecting => "Reading…".to_owned(),
        EntryState::Queued => "Waiting to convert…".to_owned(),
        EntryState::Converting(progress) => format!(
            "{} · {}%",
            progress.stage.label(),
            format::percent(progress.overall_fraction())
        ),
        EntryState::Uploading(progress) => {
            if progress.files_total == 0 {
                "Connecting to the Xbox…".to_owned()
            } else if progress.files_done >= progress.files_total {
                "Uploaded to the Xbox".to_owned()
            } else if let Some(notice) = &progress.notice {
                notice.clone()
            } else {
                let mut text = if progress.file.is_empty() {
                    "Uploading to the Xbox".to_owned()
                } else {
                    format!("Uploading {}", progress.file)
                };
                if let Some(rate) = progress.bytes_per_sec {
                    text.push_str(&format!(" · {}", format::speed(rate)));
                    if rate >= 1.0 {
                        let remaining = progress.total.saturating_sub(progress.done);
                        let seconds = (remaining as f64 / rate).ceil() as u64;
                        text.push_str(&format!(" · {} left", format::duration(seconds)));
                    }
                }
                text
            }
        }
        EntryState::Done { uploaded: true } => "Converted · uploaded to the Xbox".to_owned(),
        EntryState::Done { uploaded: false } => "Converted".to_owned(),
        EntryState::Cancelled => "Cancelled".to_owned(),
        EntryState::Failed(message) => format!("Failed: {message}"),
        EntryState::Ready => match &entry.info {
            Some(info) => format!(
                "{}{} · {} · Title ID {}",
                if info.kind == SourceKind::Folder {
                    "Folder · "
                } else {
                    ""
                },
                info.content_type.description(),
                format::size(info.data_size),
                info.title_id_string()
            ),
            None => "Ready".to_owned(),
        },
    }
}

fn icon_classes(state: &EntryState) -> &'static [&'static str] {
    match state {
        EntryState::Done { .. } => &["success"],
        EntryState::Failed(_) => &["error"],
        _ => &["dim-label"],
    }
}

fn icon_for(entry: &IsoEntry) -> &'static str {
    match &entry.state {
        EntryState::Inspecting | EntryState::Queued | EntryState::Converting(_) => {
            "view-refresh-symbolic"
        }
        EntryState::Uploading(_) => "go-up-symbolic",
        EntryState::Done { .. } => "object-select-symbolic",
        EntryState::Failed(_) => "dialog-error-symbolic",
        EntryState::Cancelled => "media-playback-stop-symbolic",
        EntryState::Ready if entry.is_folder() => "folder-symbolic",
        EntryState::Ready => "media-optical-symbolic",
    }
}
