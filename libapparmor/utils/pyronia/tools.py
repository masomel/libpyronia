# ----------------------------------------------------------------------
#    Copyright (C) 2013 Kshitij Gupta <kgupta8592@gmail.com>
#
#    This program is free software; you can redistribute it and/or
#    modify it under the terms of version 2 of the GNU General Public
#    License as published by the Free Software Foundation.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
# ----------------------------------------------------------------------
import os
import sys

import pyronia.aa as pyronia
import pyronia.ui as aaui
from pyronia.common import user_perm, cmd

# setup module translations
from pyronia.translations import init_translation
_ = init_translation()

class aa_tools:
    def __init__(self, tool_name, args):
        self.name = tool_name
        self.profiledir = args.dir
        self.profiling = args.program
        self.check_profile_dir()
        self.silent = None
        self.do_reload = args.do_reload

        if tool_name in ['audit']:
            self.remove = args.remove
        elif tool_name == 'autodep':
            self.force = args.force
            self.aa_mountpoint = pyronia.check_for_apparmor()
        elif tool_name == 'cleanprof':
            self.silent = args.silent

    def check_profile_dir(self):
        if self.profiledir:
            pyronia.profile_dir = pyronia.get_full_path(self.profiledir)
            if not os.path.isdir(pyronia.profile_dir):
                raise pyronia.AppArmorException("%s is not a directory." % self.profiledir)

        if not user_perm(pyronia.profile_dir):
            raise pyronia.AppArmorException("Cannot write to profile directory: %s" % (pyronia.profile_dir))

    def get_next_to_profile(self):
        '''Iterator function to walk the list of arguments passed'''

        for p in self.profiling:
            if not p:
                continue

            program = None
            profile = None
            if os.path.exists(p) or p.startswith('/'):
                fq_path = pyronia.get_full_path(p).strip()
                if os.path.commonprefix([pyronia.profile_dir, fq_path]) == pyronia.profile_dir:
                    program = None
                    profile = fq_path
                else:
                    program = fq_path
                    profile = pyronia.get_profile_filename(fq_path)
            else:
                which = pyronia.which(p)
                if which is not None:
                    program = pyronia.get_full_path(which)
                    profile = pyronia.get_profile_filename(program)
                elif os.path.exists(os.path.join(pyronia.profile_dir, p)):
                    program = None
                    profile = pyronia.get_full_path(os.path.join(pyronia.profile_dir, p)).strip()
                else:
                    if '/' not in p:
                        aaui.UI_Info(_("Can't find %(program)s in the system path list. If the name of the application\nis correct, please run 'which %(program)s' as a user with correct PATH\nenvironment set up in order to find the fully-qualified path and\nuse the full path as parameter.") % { 'program': p })
                    else:
                        aaui.UI_Info(_("%s does not exist, please double-check the path.") % p)
                    continue

            yield (program, profile)

    def act(self):
        # used by aa-cleanprof
        pyronia.read_profiles()

        for (program, profile) in self.get_next_to_profile():
            if program is None:
                program = profile

            if not program or not(os.path.exists(program) or pyronia.profile_exists(program)):
                if program and not program.startswith('/'):
                    program = aaui.UI_GetString(_('The given program cannot be found, please try with the fully qualified path name of the program: '), '')
                else:
                    aaui.UI_Info(_("%s does not exist, please double-check the path.") % program)
                    sys.exit(1)

            if program and pyronia.profile_exists(program):
                if self.name == 'cleanprof':
                    self.clean_profile(program)

                else:
                    filename = pyronia.get_profile_filename(program)

                    if not os.path.isfile(filename) or pyronia.is_skippable_file(filename):
                        aaui.UI_Info(_('Profile for %s not found, skipping') % program)

                    else:
                        # One simply does not walk in here!
                        raise pyronia.AppArmorException('Unknown tool: %s' % self.name)

                    self.reload_profile(profile)

            else:
                if '/' not in program:
                    aaui.UI_Info(_("Can't find %(program)s in the system path list. If the name of the application\nis correct, please run 'which %(program)s' as a user with correct PATH\nenvironment set up in order to find the fully-qualified path and\nuse the full path as parameter.") % { 'program': program })
                else:
                    aaui.UI_Info(_("%s does not exist, please double-check the path.") % program)
                    sys.exit(1)

    def cmd_disable(self):
        pyronia.read_profiles()

        for (program, profile) in self.get_next_to_profile():

            output_name = profile if program is None else program

            if not os.path.isfile(profile) or pyronia.is_skippable_file(profile):
                aaui.UI_Info(_('Profile for %s not found, skipping') % output_name)
                continue

            aaui.UI_Info(_('Disabling %s.') % output_name)
            self.disable_profile(profile)

            self.unload_profile(profile)

    def cmd_enforce(self):
        pyronia.read_profiles()

        for (program, profile) in self.get_next_to_profile():

            output_name = profile if program is None else program

            if not os.path.isfile(profile) or pyronia.is_skippable_file(profile):
                aaui.UI_Info(_('Profile for %s not found, skipping') % output_name)
                continue

            pyronia.set_enforce(profile, program)

            self.reload_profile(profile)

    def cmd_complain(self):
        pyronia.read_profiles()

        for (program, profile) in self.get_next_to_profile():

            output_name = profile if program is None else program

            if not os.path.isfile(profile) or pyronia.is_skippable_file(profile):
                aaui.UI_Info(_('Profile for %s not found, skipping') % output_name)
                continue

            pyronia.set_complain(profile, program)

            self.reload_profile(profile)

    def cmd_audit(self):
        pyronia.read_profiles()

        for (program, profile) in self.get_next_to_profile():

            output_name = profile if program is None else program

            if not os.path.isfile(profile) or pyronia.is_skippable_file(profile):
                aaui.UI_Info(_('Profile for %s not found, skipping') % output_name)
                continue

            # keep this to allow toggling 'audit' flags
            if not self.remove:
                aaui.UI_Info(_('Setting %s to audit mode.') % output_name)
            else:
                aaui.UI_Info(_('Removing audit mode from %s.') % output_name)
            pyronia.change_profile_flags(profile, program, 'audit', not self.remove)

            disable_link = '%s/disable/%s' % (pyronia.profile_dir, os.path.basename(profile))

            if os.path.exists(disable_link):
                aaui.UI_Info(_('\nWarning: the profile %s is disabled. Use aa-enforce or aa-complain to enable it.') % os.path.basename(profile))

            self.reload_profile(profile)

    def cmd_autodep(self):
        pyronia.read_profiles()

        for (program, profile) in self.get_next_to_profile():
            if not program:
                aaui.UI_Info(_('Please pass an application to generate a profile for, not a profile itself - skipping %s.') % profile)
                continue

            pyronia.check_qualifiers(program)

            if os.path.exists(pyronia.get_profile_filename(program)) and not self.force:
                aaui.UI_Info(_('Profile for %s already exists - skipping.') % program)
            else:
                pyronia.autodep(program)
                if self.aa_mountpoint:
                    pyronia.reload(program)

    def clean_profile(self, program):
        filename = pyronia.get_profile_filename(program)
        import pyronia.cleanprofile as cleanprofile
        prof = cleanprofile.Prof(filename)
        cleanprof = cleanprofile.CleanProf(True, prof, prof)
        deleted = cleanprof.remove_duplicate_rules(program)
        aaui.UI_Info(_("\nDeleted %s rules.") % deleted)
        pyronia.changed[program] = True

        if filename:
            if not self.silent:
                q = aaui.PromptQuestion()
                q.title = 'Changed Local Profiles'
                q.explanation = _('The local profile for %(program)s in file %(file)s was changed. Would you like to save it?') % { 'program': program, 'file': filename }
                q.functions = ['CMD_SAVE_CHANGES', 'CMD_VIEW_CHANGES', 'CMD_ABORT']
                q.default = 'CMD_VIEW_CHANGES'
                q.options = []
                q.selected = 0
                ans = ''
                arg = None
                while ans != 'CMD_SAVE_CHANGES':
                    ans, arg = q.promptUser()
                    if ans == 'CMD_SAVE_CHANGES':
                        pyronia.write_profile_ui_feedback(program)
                        self.reload_profile(filename)
                    elif ans == 'CMD_VIEW_CHANGES':
                        #oldprofile = pyronia.serialize_profile(pyronia.original_aa[program], program, '')
                        newprofile = pyronia.serialize_profile(pyronia.aa[program], program, '')
                        pyronia.display_changes_with_comments(filename, newprofile)
            else:
                pyronia.write_profile_ui_feedback(program)
                self.reload_profile(filename)
        else:
            raise pyronia.AppArmorException(_('The profile for %s does not exists. Nothing to clean.') % program)

    def enable_profile(self, filename):
        pyronia.delete_symlink('disable', filename)

    def disable_profile(self, filename):
        pyronia.create_symlink('disable', filename)

    def unload_profile(self, profile):
        if not self.do_reload:
            return

        # FIXME: should ensure profile is loaded before unloading
        cmd_info = cmd([pyronia.parser, '-I%s' % pyronia.profile_dir, '--base', pyronia.profile_dir, '-R', profile])

        if cmd_info[0] != 0:
            raise pyronia.AppArmorException(cmd_info[1])

    def reload_profile(self, profile):
        if not self.do_reload:
            return

        cmd_info = cmd([pyronia.parser, '-I%s' % pyronia.profile_dir, '--base', pyronia.profile_dir, '-r', profile])

        if cmd_info[0] != 0:
            raise pyronia.AppArmorException(cmd_info[1])
