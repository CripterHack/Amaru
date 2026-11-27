<script lang="ts">
  import AlertOctagon from 'lucide-svelte/icons/octagon-alert';
  import AlertTriangle from 'lucide-svelte/icons/triangle-alert';
  import ArrowLeft from 'lucide-svelte/icons/arrow-left';
  import ArrowRight from 'lucide-svelte/icons/arrow-right';
  import Bell from 'lucide-svelte/icons/bell';
  import Brain from 'lucide-svelte/icons/brain';
  import ChevronRight from 'lucide-svelte/icons/chevron-right';
  import CircleHelp from 'lucide-svelte/icons/circle-help';
  import Clock from 'lucide-svelte/icons/clock';
  import Cog from 'lucide-svelte/icons/cog';
  import Cpu from 'lucide-svelte/icons/cpu';
  import Download from 'lucide-svelte/icons/download';
  import FileCheck from 'lucide-svelte/icons/file-check';
  import FileSearch from 'lucide-svelte/icons/file-search';
  import FileText from 'lucide-svelte/icons/file-text';
  import HardDrive from 'lucide-svelte/icons/hard-drive';
  import Info from 'lucide-svelte/icons/info';
  import Key from 'lucide-svelte/icons/key';
  import Loader from 'lucide-svelte/icons/loader';
  import Lock from 'lucide-svelte/icons/lock';
  import MessageCircle from 'lucide-svelte/icons/message-circle';
  import Moon from 'lucide-svelte/icons/moon';
  import Power from 'lucide-svelte/icons/power';
  import RefreshCw from 'lucide-svelte/icons/refresh-cw';
  import Rocket from 'lucide-svelte/icons/rocket';
  import Search from 'lucide-svelte/icons/search';
  import Settings from 'lucide-svelte/icons/settings';
  import Shield from 'lucide-svelte/icons/shield';
  import ShieldAlert from 'lucide-svelte/icons/shield-alert';
  import ShieldCheck from 'lucide-svelte/icons/shield-check';
  import ShieldOff from 'lucide-svelte/icons/shield-off';
  import Sun from 'lucide-svelte/icons/sun';
  import Trash2 from 'lucide-svelte/icons/trash-2';
  import User from 'lucide-svelte/icons/user';
  import Users from 'lucide-svelte/icons/users';
  import Video from 'lucide-svelte/icons/video';
  import Wrench from 'lucide-svelte/icons/wrench';
  import X from 'lucide-svelte/icons/x';
  import Zap from 'lucide-svelte/icons/zap';

  export let name: string;
  export let size: number | string = 24;
  export let strokeWidth = 2;
  export let class_ = '';
  export let spin = false;

  const components: Record<string, typeof CircleHelp> = {
    'alert-octagon': AlertOctagon,
    'alert-triangle': AlertTriangle,
    'arrow-left': ArrowLeft,
    'arrow-right': ArrowRight,
    bell: Bell,
    brain: Brain,
    'chevron-right': ChevronRight,
    'circle-help': CircleHelp,
    clock: Clock,
    cog: Cog,
    cpu: Cpu,
    download: Download,
    'file-check': FileCheck,
    'file-search': FileSearch,
    'file-text': FileText,
    'hard-drive': HardDrive,
    info: Info,
    key: Key,
    loader: Loader,
    lock: Lock,
    'message-circle': MessageCircle,
    moon: Moon,
    power: Power,
    'refresh-cw': RefreshCw,
    rocket: Rocket,
    search: Search,
    settings: Settings,
    shield: Shield,
    'shield-alert': ShieldAlert,
    'shield-check': ShieldCheck,
    'shield-off': ShieldOff,
    sun: Sun,
    'trash-2': Trash2,
    user: User,
    users: Users,
    video: Video,
    wrench: Wrench,
    x: X,
    zap: Zap
  };
  $: component = components[name] ?? CircleHelp;
</script>

<svelte:component this={component} {size} {strokeWidth}
  class={[class_, $$restProps.class, spin && 'animate-spin'].filter(Boolean).join(' ')}
  aria-hidden="true"
/>
